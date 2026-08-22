"""Proof tests for the Gmail connection: Vault app secret, sealed grants.

No real secret and no real Vault. The seal is injected via
``rest_protect.set_test_protector`` so nothing here calls DPAPI.
"""

import ast
import json
from pathlib import Path

import pytest

from mikeasick_connections import gmail_secrets

REPO = Path(__file__).resolve().parents[1]
PKG = REPO / "src" / "mikeasick_connections"
IDENTITY = "mike-email-gmail-personal"

FAKE_CLIENT_ID = "fake-client-id.apps.googleusercontent.com"
FAKE_SECRET = "fake-client-secret-do-not-use"
FAKE_REFRESH = "fake-refresh-token-do-not-use"

# The seven fields both Vault entries carry, verbatim (proposal.md).
VAULT_FIELDS = {
    "client_id": FAKE_CLIENT_ID,
    "client_secret": FAKE_SECRET,
    "token_url": "https://oauth2.googleapis.com/token",
    "grant_type": "oauth2_refresh",
    "granted_reference": "",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "redirect_uris": "http://localhost",
}

READONLY = ["https://www.googleapis.com/auth/gmail.readonly"]
MODIFY = ["https://www.googleapis.com/auth/gmail.modify"]
CALENDAR = ["https://www.googleapis.com/auth/calendar.readonly"]


def _xor(data: bytes) -> bytes:
    return bytes(b ^ 0xA5 for b in data)


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Sealed store rooted in tmp_path, with an injected (non-DPAPI) protector."""
    gmail_secrets.rest_protect.set_test_protector(_xor, _xor)
    monkeypatch.setattr(gmail_secrets, "STORE_ROOT", tmp_path / "gmail")
    yield tmp_path / "gmail"
    gmail_secrets.rest_protect.set_test_protector(None)


@pytest.fixture
def no_vault(monkeypatch):
    """Any Vault read is a test failure."""
    def boom(identity):
        raise AssertionError(f"read_app_secret reached Vault for {identity}")
    monkeypatch.setattr(gmail_secrets, "read_app_secret", boom)


class _StubRequest:
    """Stands in for google.auth.transport.Request. Returns a 200 token body."""

    def __init__(self):
        self.calls = []

    def __call__(self, url=None, method="POST", body=None, headers=None, **kw):
        self.calls.append((url, body))
        payload = json.dumps({
            "access_token": "fake-access-token",
            "expires_in": 3599,
            "token_type": "Bearer",
        }).encode()
        return type("Resp", (), {"status": 200, "data": payload})()


def _grant(store_root, scopes=READONLY):
    gmail_secrets.write_grant(
        IDENTITY, scopes,
        client_id=FAKE_CLIENT_ID,
        client_secret=FAKE_SECRET,
        refresh_token=FAKE_REFRESH,
        token_uri=VAULT_FIELDS["token_url"],
    )
    return gmail_secrets.store_path(IDENTITY)


# --- Task 8 -----------------------------------------------------------------

def test_client_config_comes_from_vault_not_disk(store, monkeypatch):
    """Fails when absent: the flow is built from a client-secrets file that this
    change deletes, so consent needs a file that will not exist."""
    monkeypatch.setattr(gmail_secrets, "read_app_secret", lambda identity: dict(VAULT_FIELDS))

    seen = {}

    class _Flow:
        @classmethod
        def from_client_config(cls, config, scopes, **kw):
            seen["config"] = config
            seen["scopes"] = scopes
            return cls()

        @classmethod
        def from_client_secrets_file(cls, *a, **kw):  # pragma: no cover
            raise AssertionError("consent opened a client-secrets file")

        def run_local_server(self, **kw):
            return gmail_secrets.Credentials.from_authorized_user_info({
                "client_id": FAKE_CLIENT_ID,
                "client_secret": FAKE_SECRET,
                "refresh_token": FAKE_REFRESH,
                "token_uri": VAULT_FIELDS["token_url"],
            }, READONLY)

    monkeypatch.setattr(gmail_secrets, "InstalledAppFlow", _Flow)
    gmail_secrets.run_consent(IDENTITY, READONLY)

    assert seen["config"]["installed"]["client_id"] == FAKE_CLIENT_ID
    assert seen["scopes"] == READONLY

    source = (PKG / "gmail_auth.py").read_text(encoding="utf-8")
    for name in ("credentials.json", "token.json", "token-calendar.json", "token-modify.json"):
        assert name not in source, f"gmail_auth still names {name}"


# --- Task 9 -----------------------------------------------------------------

def test_token_url_is_mapped_to_token_uri():
    """Fails when absent: the Vault dict is copied through unmapped, so the flow
    has no token endpoint and dies later as a confusing exchange error."""
    config = gmail_secrets.build_client_config(dict(VAULT_FIELDS))
    installed = config["installed"]
    assert installed["token_uri"] == VAULT_FIELDS["token_url"]
    assert "token_url" not in installed
    assert "token_url" not in config
    assert installed["auth_uri"] == VAULT_FIELDS["auth_uri"]
    assert "granted_reference" not in installed


def test_client_config_without_token_endpoint_is_a_hard_error():
    """Fails when absent: a missing endpoint is silently defaulted to a URL baked
    into our code, so a Vault edit stops being authoritative."""
    fields = dict(VAULT_FIELDS)
    fields.pop("token_url")
    with pytest.raises(gmail_secrets.AppSecretIncomplete):
        gmail_secrets.build_client_config(fields)


# --- Task 10 ----------------------------------------------------------------

def test_refresh_succeeds_with_vault_unavailable(store, no_vault):
    """Fails when absent: the refresh path reaches for Vault, so every scan needs
    an unlocked Vault. If the store omits the client secret it raises
    RefreshError locally before the endpoint is reached -- the same failure."""
    _grant(store)
    creds = gmail_secrets.read_grant(IDENTITY, READONLY)
    request = _StubRequest()
    creds.refresh(request)
    assert creds.token == "fake-access-token"
    assert request.calls, "refresh never reached the token endpoint"


# --- Task 11 ----------------------------------------------------------------

def test_consent_with_locked_vault_fails_actionably(store, monkeypatch):
    """Fails when absent: the failure is a bare exception or a silent skip, and
    the operator cannot tell what to do."""
    def locked(identity):
        raise gmail_secrets.VaultUnavailable("vault is locked")
    monkeypatch.setattr(gmail_secrets, "read_app_secret", locked)

    with pytest.raises(gmail_secrets.VaultUnavailable) as caught:
        gmail_secrets.run_consent(IDENTITY, READONLY)
    message = str(caught.value)
    assert IDENTITY in message
    assert "gmail.readonly" in message
    assert "vault_unlock.py" in message


def test_missing_grant_names_the_grant_command(store, no_vault):
    """Fails when absent: an absent store reads as a generic file error instead of
    naming the command that obtains a grant."""
    with pytest.raises(gmail_secrets.GrantMissing) as caught:
        gmail_secrets.read_grant(IDENTITY, READONLY)
    assert "gmail-grant" in str(caught.value)


# --- Task 12 ----------------------------------------------------------------

def test_all_three_scope_sets_sealed_in_one_store(store):
    """Fails when absent: a scope set is stored unsealed, the client secret is
    written in cleartext, or a later grant overwrites an earlier one."""
    for scopes in (READONLY, MODIFY, CALENDAR):
        _grant(store, scopes)

    files = sorted(store.glob("*.json"))
    assert len(files) == 1, f"expected one store file, found {files}"
    data = json.loads(files[0].read_text(encoding="utf-8"))

    # Client identity once per file -- all three scope sets share one OAuth client.
    assert data["client_id"] == FAKE_CLIENT_ID
    assert data["token_uri"] == VAULT_FIELDS["token_url"]
    assert gmail_secrets.rest_protect.is_sealed(data["client_secret"])

    assert set(data["grants"]) == {
        gmail_secrets.scope_key(s) for s in (READONLY, MODIFY, CALENDAR)
    }
    for key, entry in data["grants"].items():
        assert gmail_secrets.rest_protect.is_sealed(entry["refresh_token"]), key
        assert "token" not in entry, f"{key} stored an access token"

    raw = files[0].read_text(encoding="utf-8")
    assert FAKE_SECRET not in raw
    assert FAKE_REFRESH not in raw

    # Re-granting one scope set leaves the other two readable.
    _grant(store, MODIFY)
    for scopes in (READONLY, CALENDAR):
        assert gmail_secrets.read_grant(IDENTITY, scopes).refresh_token == FAKE_REFRESH


# --- Task 13 ----------------------------------------------------------------

def test_no_secret_is_logged(store, capsys, monkeypatch):
    """Fails when absent: a secret reaches the transcript or a run log, which is
    the outcome this whole change exists to remove."""
    monkeypatch.setattr(gmail_secrets, "read_app_secret", lambda identity: dict(VAULT_FIELDS))
    _grant(store)
    gmail_secrets.read_grant(IDENTITY, READONLY)
    gmail_secrets.describe_store(IDENTITY)

    def locked(identity):
        raise gmail_secrets.VaultUnavailable("vault is locked")
    monkeypatch.setattr(gmail_secrets, "read_app_secret", locked)
    with pytest.raises(gmail_secrets.VaultUnavailable) as caught:
        gmail_secrets.run_consent(IDENTITY, READONLY)

    captured = capsys.readouterr()
    for secret in (FAKE_SECRET, FAKE_REFRESH):
        assert secret not in captured.out
        assert secret not in captured.err
        assert secret not in str(caught.value)
        assert secret not in repr(caught.value)


# --- Task 14 ----------------------------------------------------------------

SCRIPTS = ("src/mikeasick_connections/cli.py",)
BANNED_CALLS = {"InstalledAppFlow", "seal", "reveal", "from_client_config",
                "from_authorized_user_info", "from_client_secrets_file"}
SHARED = {"run_consent", "read_grant", "write_grant", "read_app_secret",
          "build_client_config", "store_path", "describe_store", "scope_key"}


def _called_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


@pytest.mark.parametrize("rel", SCRIPTS)
def test_scripts_and_library_share_one_implementation(rel):
    """Fails when absent: the scripts carry their own copy of the flow and drift
    from gmail_secrets, so fixing one leaves the other broken."""
    path = REPO / rel
    assert path.is_file(), f"missing {rel}"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    called = _called_names(tree)

    leaked = called & BANNED_CALLS
    assert not leaked, f"{rel} re-implements the flow: {sorted(leaked)}"
    assert called & SHARED, f"{rel} calls no shared gmail_secrets function"
    assert "oauth2.googleapis.com" not in source, f"{rel} hard-codes the token endpoint"
