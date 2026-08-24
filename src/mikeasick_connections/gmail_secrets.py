"""Gmail OAuth secrets: app secret from Zoho Vault, grants sealed on disk.

Vault is read only when a fresh consent is required. Ordinary refresh reads the
sealed store, so a locked Vault never breaks a scan.

Store: ``~/.fnx/gmail/<identity>.json``, one file per identity.
Top level carries ``client_id``, ``token_uri``, and a sealed ``client_secret``
(an identity's scope sets share one OAuth client). ``grants`` carries one entry
per scope set, each with a sealed ``refresh_token``. No access token is stored.

Nothing here prints a secret.
"""

import json
import subprocess
import sys
from pathlib import Path

from mikeasick_connections.identities import resolve

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

STORE_ROOT = Path.home() / ".fnx" / "gmail"

UNLOCK_HINT = (
    "run the fnx-core:zoho-vault helpers vault_login.py then vault_unlock.py"
)
GRANT_HINT = "run `gmail-grant` for that identity and scope set"


class GmailSecretError(Exception):
    """Base for every failure in this module. Never carries a secret value."""


class VaultUnavailable(GmailSecretError):
    """Vault is locked, logged out, or the entry could not be read."""


class GrantMissing(GmailSecretError):
    """No sealed grant on disk for this identity and scope set."""


class AppSecretIncomplete(GmailSecretError):
    """The Vault entry is missing a field the client config requires."""


def _fnx_setup_scripts() -> Path:
    """fnx-setup's scripts/ directory, from installed_plugins.json installPath.

    Never path math on __file__: fnx-* plugins are versioned independently and
    the cache is <plugin>/<version>/ (fnx-core plugin-contract rule 1).
    """
    registry = Path.home() / ".claude" / "plugins" / "installed_plugins.json"
    try:
        plugins = json.loads(registry.read_text(encoding="utf-8"))["plugins"]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise GmailSecretError(f"unreadable plugin registry {registry}") from exc
    for key, records in plugins.items():
        if key.split("@")[0] != "fnx-setup":
            continue
        for rec in records if isinstance(records, list) else [records]:
            path = Path(rec["installPath"]) / "scripts"
            if path.is_dir():
                return path
    raise GmailSecretError(
        f"fnx-setup not found in {registry}; install the fnx-setup plugin"
    )


def _load_fnx():
    """The seal and the atomic writer, resolved across plugin boundaries.

    `rest_protect` lived in fnx-setup until it moved to fnx-core (measured
    2026-08-24: absent from fnx-setup 0.47.50, present in fnx-core 0.21.187).
    `core_locator.load_core_module` is the vendor's own resolver for exactly
    that -- fnx-setup 0.47.50 uses it to reach `rest_protect` too -- so it keeps
    working across the next move. Importing by a fixed location does not.
    """
    scripts = str(_fnx_setup_scripts())
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from lifecycle.engine import atomic_write_json as _aw
    try:
        import core_locator
    except ImportError as exc:  # pragma: no cover - fnx-setup layout changed
        raise GmailSecretError(
            f"fnx-setup at {scripts} has no core_locator; cannot resolve the "
            f"seal helper"
        ) from exc
    try:
        _rp = core_locator.load_core_module("rest_protect", __file__)
    except ImportError as exc:
        raise GmailSecretError(
            "could not resolve rest_protect from fnx-core; is the fnx-core "
            "plugin installed?"
        ) from exc
    return _rp, _aw


rest_protect, atomic_write_json = _load_fnx()


# --- Vault ------------------------------------------------------------------

def read_app_secret(identity: str) -> dict:
    """The identity's Vault entry as a flat {label: value} dict, in memory only.

    Runs `zv` as a subprocess and keeps stdout in this process. The value never
    reaches a file, a log, or argv.
    """
    try:
        entry_id = resolve(identity).vault_entry
    except KeyError as exc:
        raise GmailSecretError(str(exc)) from None
    try:
        proc = subprocess.run(
            ["zv", "get", "-id", entry_id, "--output", "json", "--not-safe"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VaultUnavailable(
            f"could not run zv for {identity} ({type(exc).__name__}); {UNLOCK_HINT}"
        ) from exc
    if proc.returncode != 0:
        raise VaultUnavailable(
            f"zv exited {proc.returncode} reading the entry for {identity}; {UNLOCK_HINT}"
        )
    try:
        rows = json.loads(proc.stdout)["secret"]["secretData"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        # Deliberately does not echo stdout -- it holds the secret.
        raise VaultUnavailable(
            f"zv returned no secret payload for {identity}; {UNLOCK_HINT}"
        ) from exc
    # granted_reference is out of scope for this capability: never read.
    return {r["label"]: r["value"] for r in rows if r["label"] != "granted_reference"}


def build_client_config(app_secret: dict) -> dict:
    """The installed-app client config, in memory.

    Maps the Vault spelling `token_url` onto the `token_uri` key the Google
    client library expects. This is the one place that mapping happens.
    """
    token_uri = app_secret.get("token_url") or app_secret.get("token_uri")
    if not token_uri:
        raise AppSecretIncomplete(
            "the Vault entry has no token endpoint (token_url); "
            "fix the entry -- the endpoint is never defaulted in our code"
        )
    for field in ("client_id", "client_secret", "auth_uri"):
        if not app_secret.get(field):
            raise AppSecretIncomplete(f"the Vault entry has no {field}")
    redirect = app_secret.get("redirect_uris") or "http://localhost"
    return {
        "installed": {
            "client_id": app_secret["client_id"],
            "client_secret": app_secret["client_secret"],
            "auth_uri": app_secret["auth_uri"],
            "token_uri": token_uri,
            "redirect_uris": [u.strip() for u in redirect.split(",") if u.strip()],
        }
    }


# --- Sealed store -----------------------------------------------------------

def scope_key(scopes) -> str:
    """Stable key for a scope set. Order-independent."""
    return " ".join(sorted(scopes))


def store_path(identity: str) -> Path:
    return STORE_ROOT / f"{identity}.json"


def _read_store(identity: str) -> dict:
    path = store_path(identity)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GmailSecretError(f"unreadable Gmail store {path}") from exc


def write_grant(identity, scopes, *, client_id, client_secret, refresh_token,
                token_uri) -> Path:
    """Seal one grant into the identity's store, leaving other scope sets intact."""
    path = store_path(identity)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _read_store(identity)
    data["client_id"] = client_id
    data["token_uri"] = token_uri
    data["client_secret"] = rest_protect.seal(client_secret, store=path)
    grants = data.setdefault("grants", {})
    grants[scope_key(scopes)] = {
        "refresh_token": rest_protect.seal(refresh_token, store=path),
        "scopes": sorted(scopes),
    }
    atomic_write_json(path, data, owner_only=True)
    return path


def read_grant(identity, scopes) -> Credentials:
    """Credentials for one scope set, revealed in memory. Never touches Vault."""
    data = _read_store(identity)
    key = scope_key(scopes)
    entry = (data.get("grants") or {}).get(key)
    if entry is None:
        raise GrantMissing(
            f"no sealed grant for {identity} scope set '{key}'; {GRANT_HINT}"
        )
    path = store_path(identity)
    return Credentials.from_authorized_user_info({
        "client_id": data["client_id"],
        "client_secret": rest_protect.reveal(data["client_secret"], store=path),
        "refresh_token": rest_protect.reveal(entry["refresh_token"], store=path),
        "token_uri": data["token_uri"],
    }, sorted(scopes))


def describe_store(identity: str) -> dict:
    """Identity, scope sets held, and whether each is sealed. No values."""
    data = _read_store(identity)
    grants = data.get("grants") or {}
    return {
        "identity": identity,
        "path": str(store_path(identity)),
        "client_secret_sealed": rest_protect.is_sealed(data.get("client_secret")),
        "scope_sets": {
            key: rest_protect.is_sealed(entry.get("refresh_token"))
            for key, entry in sorted(grants.items())
        },
    }


# --- Consent ----------------------------------------------------------------

def run_consent(identity, scopes, *, login_hint=None, open_browser=True,
                browser=None) -> Credentials:
    """Fresh Allow for one identity and scope set, sealed into the store.

    ``open_browser=False`` prints the authorization URL instead of launching a
    browser. ``browser`` is a registered `webbrowser` name -- see
    `scanner.chrome_profiles.register_opener`, which pins consent to the Chrome
    profile already signed in as that account. The default browser is whichever
    account its profile holds, and `login_hint` only pre-fills the picker.
    """
    key = scope_key(scopes)
    try:
        app_secret = read_app_secret(identity)
    except VaultUnavailable as exc:
        raise VaultUnavailable(
            f"consent needed for {identity} scope set '{key}' but Zoho Vault is "
            f"unavailable: {exc}. To unlock: {UNLOCK_HINT}"
        ) from None
    config = build_client_config(app_secret)
    flow = InstalledAppFlow.from_client_config(config, scopes)
    creds = flow.run_local_server(
        port=0, login_hint=login_hint, open_browser=open_browser, browser=browser)
    write_grant(
        identity, scopes,
        client_id=config["installed"]["client_id"],
        client_secret=config["installed"]["client_secret"],
        refresh_token=creds.refresh_token,
        token_uri=config["installed"]["token_uri"],
    )
    return creds
