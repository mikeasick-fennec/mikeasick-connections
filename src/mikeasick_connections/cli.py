"""Console entry points: `gmail-grant` and `gmail-check`.

Thin wrappers. Every mechanism lives in `gmail_secrets`; a script that grows its
own copy of the OAuth flow drifts from the library, and then fixing one leaves
the other broken.

Neither prints a secret.
"""

import argparse
import sys

from mikeasick_connections import chrome_profiles, gmail_auth, gmail_secrets
from mikeasick_connections.identities import EMAIL_IDENTITIES

SCOPE_SETS = {
    "gmail": gmail_auth.GMAIL_SCOPES,
    "modify": gmail_auth.GMAIL_MODIFY_SCOPES,
    "calendar": gmail_auth.CALENDAR_SCOPES,
}


def _account_arg(parser):
    parser.add_argument("--account", default="personal",
                        choices=sorted(EMAIL_IDENTITIES),
                        help="which connection (default: personal)")


def grant() -> int:
    """First grant for one identity and scope set. Needs an unlocked Vault."""
    ap = argparse.ArgumentParser(prog="gmail-grant", description=grant.__doc__)
    _account_arg(ap)
    ap.add_argument("--scopes", default="gmail", choices=sorted(SCOPE_SETS))
    ap.add_argument("--no-browser", action="store_true",
                    help="print the authorization URL instead of opening a browser")
    ap.add_argument("--chrome-profile", metavar="ACCOUNT_OR_DIR",
                    help="open consent in the Chrome profile signed in as this "
                         "account (default: the connection's own address)")
    ap.add_argument("--list-profiles", action="store_true",
                    help="print the Chrome profile directory -> account map and exit")
    args = ap.parse_args()

    if args.list_profiles:
        for directory, email in chrome_profiles.profiles().items():
            print(f"  {directory:12s} {email or '(signed out)'}")
        return 0

    identity = gmail_auth.identity_for(args.account)
    scopes = SCOPE_SETS[args.scopes]
    hint = gmail_auth.ACCOUNTS[args.account]["login_hint"]
    print(f"[gmail-grant] consent for {identity} scope set '{args.scopes}'", flush=True)

    browser = None
    if not args.no_browser:
        # Consent must land in the profile signed in as this account; the default
        # browser is whichever account ITS profile holds.
        try:
            browser = chrome_profiles.register_opener(args.chrome_profile or hint)
        except chrome_profiles.ProfileNotFound as exc:
            print(f"[gmail-grant] {exc}", file=sys.stderr, flush=True)
            print("[gmail-grant] re-run with --chrome-profile <dir> or --no-browser",
                  file=sys.stderr, flush=True)
            return 1
    try:
        gmail_secrets.run_consent(identity, scopes, login_hint=hint,
                                  open_browser=not args.no_browser, browser=browser)
    except gmail_secrets.GmailSecretError as exc:
        print(f"[gmail-grant] FAILED: {exc}", file=sys.stderr, flush=True)
        return 1

    described = gmail_secrets.describe_store(identity)
    print(f"[gmail-grant] sealed at {described['path']}", flush=True)
    for key, sealed in described["scope_sets"].items():
        print(f"  {'sealed  ' if sealed else 'UNSEALED'} {key}", flush=True)
    return 0


def _check_one(identity: str, scopes) -> int:
    from google.auth.exceptions import RefreshError
    from google.auth.transport.requests import Request

    key = gmail_secrets.scope_key(scopes)
    try:
        creds = gmail_secrets.read_grant(identity, scopes)
    except gmail_secrets.GmailSecretError as exc:
        print(f"[gmail-check] {identity} '{key}': {exc}", file=sys.stderr, flush=True)
        return 1
    try:
        creds.refresh(Request())
    except RefreshError as exc:
        print(f"[gmail-check] {identity} '{key}': REVOKED "
              f"({type(exc).__name__}: {str(exc)[:160]}). "
              f"Re-grant: gmail-grant --account <alias>", file=sys.stderr, flush=True)
        return 1
    print(f"[gmail-check] {identity} '{key}': live", flush=True)
    return 0


def check() -> int:
    """Exercise a sealed grant. No consent and no Vault: the store has it all."""
    ap = argparse.ArgumentParser(prog="gmail-check", description=check.__doc__)
    _account_arg(ap)
    ap.add_argument("--scopes", default="gmail",
                    choices=sorted(SCOPE_SETS) + ["all"])
    args = ap.parse_args()
    identity = gmail_auth.identity_for(args.account)
    names = sorted(SCOPE_SETS) if args.scopes == "all" else [args.scopes]
    return max(_check_one(identity, SCOPE_SETS[n]) for n in names)
