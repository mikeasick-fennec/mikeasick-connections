"""Gmail and Calendar API authentication.

Grants live sealed at `~/.fnx/gmail/<email-identity>.json`, one file per
identity, one entry per scope set (`scanner.gmail_secrets`). The OAuth app
secret comes from Zoho Vault and is read only when a fresh consent is needed,
so a locked Vault never breaks an ordinary refresh.

Two email identities are supported today:
    - mike-email-gmail-personal   (alias: account="personal")
    - mike-email-gmail-company    (alias: account="enterprise")

The `account="personal"|"enterprise"` API is preserved for back-compat;
internally it resolves to the corresponding email identity.

To obtain a first grant: `python scripts/gmail_grant.py --account <alias>`.
To check one: `python scripts/gmail_refresh.py --account <alias>`.
"""

import sys

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

from mikeasick_connections import gmail_secrets
from mikeasick_connections.identities import EMAIL_IDENTITIES, resolve

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
GMAIL_MODIFY_SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
CALENDAR_SCOPES = ["https://www.googleapis.com/auth/calendar.readonly"]
CALENDAR_EVENTS_SCOPES = ["https://www.googleapis.com/auth/calendar.events"]
ALL_SCOPES = GMAIL_SCOPES + CALENDAR_SCOPES

# Named scope sets, as `gmail-grant --scopes` spells them.
SCOPE_SETS = {
    "gmail": GMAIL_SCOPES,
    "modify": GMAIL_MODIFY_SCOPES,
    "calendar": CALENDAR_SCOPES,
    "calendar-events": CALENDAR_EVENTS_SCOPES,
}

ACCOUNTS = {
    alias: {"identity": i.name, "login_hint": i.login_hint}
    for alias, i in EMAIL_IDENTITIES.items()
}


def identity_for(account: str) -> str:
    return resolve(account).name


def _login_hint(account: str) -> str:
    return resolve(account).login_hint


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def has_grant(account: str, scopes) -> bool:
    """True if a sealed grant exists for this scope set. No refresh, no consent."""
    described = gmail_secrets.describe_store(identity_for(account))
    return gmail_secrets.scope_key(scopes) in described["scope_sets"]


def _consent(account, scopes, interactive, reason):
    """Run browser consent, or raise ConsentRequired when the caller forbade it."""
    identity = identity_for(account)
    if not interactive:
        alias = next(a for a, v in ACCOUNTS.items() if v["identity"] == identity)
        key = gmail_secrets.scope_key(scopes)
        name = next((n for n, s in SCOPE_SETS.items()
                     if gmail_secrets.scope_key(s) == key), key)
        raise gmail_secrets.ConsentRequired(
            f"{identity} scope set '{key}': {reason}; "
            f"repair with: gmail-grant --account {alias} --scopes {name}")
    return gmail_secrets.run_consent(identity, scopes, login_hint=_login_hint(account))


def _get_credentials(account, scopes, interactive=True):
    """Valid credentials for the account and scope set, from the sealed store.
    With interactive=False, a missing or revoked grant raises ConsentRequired
    instead of opening a browser and waiting."""
    identity = identity_for(account)
    try:
        creds = gmail_secrets.read_grant(identity, scopes)
    except gmail_secrets.GrantMissing:
        return _consent(account, scopes, interactive, "no sealed grant")
    if creds.valid:
        return creds
    try:
        creds.refresh(Request())
    except RefreshError as exc:
        # Refresh token revoked or expired (invalid_grant). The message names the
        # failure class, never a credential value.
        reason = f"refresh failed ({type(exc).__name__}: {str(exc)[:160]})"
        if interactive:
            print(f"[gmail_auth] {identity}: {reason}; re-running OAuth consent.",
                  file=sys.stderr, flush=True)
        return _consent(account, scopes, interactive, reason)
    # A refresh may rotate the refresh token, so reseal what we now hold.
    gmail_secrets.write_grant(
        identity, scopes,
        client_id=creds.client_id,
        client_secret=creds.client_secret,
        refresh_token=creds.refresh_token,
        token_uri=creds.token_uri,
    )
    return creds


def get_credentials(account="personal", interactive=True):
    """Get valid Gmail credentials for the specified account."""
    return _get_credentials(account, GMAIL_SCOPES, interactive)


def get_calendar_credentials(account="personal", interactive=True):
    """Get valid Calendar credentials for the specified account."""
    return _get_credentials(account, CALENDAR_SCOPES, interactive)


def has_modify_token(account="personal"):
    """True if a sealed gmail.modify grant exists (no refresh, no consent)."""
    return has_grant(account, GMAIL_MODIFY_SCOPES)


def get_modify_service(account="personal", interactive=True):
    """Gmail service with modify scope (covers drafts().create). Caller SHOULD gate
    on has_modify_token first -- with no grant this opens an interactive consent."""
    creds = _get_credentials(account, GMAIL_MODIFY_SCOPES, interactive)
    return build("gmail", "v1", credentials=creds)


def get_gmail_service(account="personal", interactive=True):
    """Build and return an authenticated Gmail API service."""
    return build("gmail", "v1", credentials=get_credentials(account, interactive))


def get_calendar_service(account="personal", interactive=True):
    """Build and return an authenticated Google Calendar API service."""
    creds = get_calendar_credentials(account, interactive)
    return build("calendar", "v3", credentials=creds)


def has_calendar_events_grant(account="personal"):
    """True if a sealed calendar.events grant exists (no refresh, no consent)."""
    return has_grant(account, CALENDAR_EVENTS_SCOPES)


def get_calendar_events_service(account="personal", interactive=True):
    """Calendar service that can create, update, and delete events. Caller SHOULD
    gate on has_calendar_events_grant first -- with no grant this opens consent."""
    creds = _get_credentials(account, CALENDAR_EVENTS_SCOPES, interactive)
    return build("calendar", "v3", credentials=creds)


def get_all_services(interactive=True):
    """Return Gmail services for every account holding a sealed readonly grant."""
    services = {}
    for name in ACCOUNTS:
        if not has_grant(name, GMAIL_SCOPES):
            continue
        try:
            services[name] = get_gmail_service(name, interactive)
        except Exception as e:
            log(f"  Skipping {name} account: {e}")
    return services


def get_all_calendar_services(interactive=True):
    """Return Calendar services for every account holding a sealed calendar grant."""
    services = {}
    for name in ACCOUNTS:
        if not has_grant(name, CALENDAR_SCOPES):
            continue
        try:
            services[name] = get_calendar_service(name, interactive)
        except Exception as e:
            log(f"  Skipping {name} calendar: {e}")
    return services


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--calendar":
        account = sys.argv[2] if len(sys.argv) > 2 else "personal"
        log(f"Authorizing Calendar API for {account}...")
        svc = get_calendar_service(account)
        cals = svc.calendarList().list(maxResults=5).execute()
        log(f"[{account}] Calendar access OK - {len(cals.get('items', []))} calendars found")
        for cal in cals.get("items", []):
            log(f"  - {cal.get('summary', 'Untitled')} ({cal.get('id', '')})")
    else:
        for name, svc in get_all_services().items():
            profile = svc.users().getProfile(userId="me").execute()
            log(f"[{name}] Authenticated as: {profile['emailAddress']} "
                f"({profile['messagesTotal']} messages)")
