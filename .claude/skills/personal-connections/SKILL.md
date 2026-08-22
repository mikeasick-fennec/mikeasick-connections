---
name: personal-connections
description: Michael's personal-level connections and the grants that reach them - the two Gmail accounts (mikeasick@gmail.com personal, michael.a.sick@serenesoftware.com enterprise), their Zoho Vault app secrets, and the sealed grant store at ~/.fnx/gmail/. Use when a task needs Gmail or Google Calendar access, when a grant is missing or revoked, when setting a connection up on a new machine, when consent lands in the wrong Google account, or when adding an account to the personal set. Not for enterprise fnx-* service connections.
---

# Personal connections

This repo holds the accounts Michael authenticates as, and the code that obtains and
holds those grants. Personal level: his own accounts on his own machine. Enterprise
service connections are fnx-* plugins and are not covered here.

Read `CLAUDE.md` in this repo for the boundary, the rules, and why the store sits
outside every repository.

## The connections

| Alias | Identity | Account | Vault entry |
|---|---|---|---|
| `personal` | `mike-email-gmail-personal` | mikeasick@gmail.com | `gmail-personal` |
| `enterprise` | `mike-email-gmail-company` | michael.a.sick@serenesoftware.com | `gmail-serene` |

Three scope sets each: `gmail` (readonly), `modify` (label, draft, send), `calendar`
(readonly). `src/mikeasick_connections/identities.py` is the single source of truth.

**Two accounts is the reason this exists.** The MCP Gmail connector supports one. Any
task touching both inboxes goes through this package.

## Using it from another project

Install from `origin/main`. Never a path install, never `-e` on this working tree:

```
pip install "git+https://github.com/mikeasick-fennec/mikeasick-connections@main"
```

Then:

```python
from mikeasick_connections import gmail_auth

services = gmail_auth.get_all_services()          # {alias: gmail service}, readonly
svc = gmail_auth.get_modify_service("personal")   # label / draft / send
cal = gmail_auth.get_all_calendar_services()
```

`get_all_services` returns only accounts holding a sealed grant, so a missing grant is a
missing key, not an exception mid-run. Gate on `gmail_auth.has_modify_token(alias)` before
reaching for modify scope: without a grant that call opens an interactive consent.

## Commands

```
gmail-check --account personal --scopes all       # is the grant live? no Vault needed
gmail-grant --account personal --scopes gmail     # obtain a grant; needs unlocked Vault
gmail-grant --list-profiles                       # Chrome profile directory -> account
```

`gmail-check` first, always. It answers "is this broken" without touching Vault and
without opening a browser.

## Obtaining a grant

Consent needs the app secret, which lives in Zoho Vault. Unlock it with the
`fnx-core:zoho-vault` helper scripts:

```
python "<fnx-core>/skills/zoho-vault/scripts/vault_login.py"
python "<fnx-core>/skills/zoho-vault/scripts/vault_unlock.py"
```

**Never run `zv login` or `zv unlock` in an agent shell** - the master password enters the
transcript. Treat that as a leaked password if it happens.

Then run `gmail-grant` once per scope set. It opens Chrome in the profile signed in as
that account and seals the returned refresh token. Re-running replaces one scope set and
leaves the others intact, which is also how a rotated app secret reaches the store.

## Wrong Google account on the consent screen

Chrome takes a profile **directory** on the command line (`--profile-directory="Profile 4"`),
not an account; the map lives in `<User Data>/Local State` under `profile.info_cache`.
`gmail-grant` resolves the account to its directory and pins consent there, so `login_hint`
alone is not relied on - it only pre-fills the picker and does not switch the session.

If the account is signed out of every profile, pass the directory:
`gmail-grant --chrome-profile "Profile 3"`. To complete consent by hand in a window you
choose, `--no-browser` prints the URL instead.

## A new machine

Install from `origin/main`, unlock Vault, run `gmail-grant` per scope set. The sealed store
does not travel: DPAPI binds it to one Windows user on one machine, which is what makes the
file useless to anything else. Copying `~/.fnx/gmail/*.json` to a second machine produces a
file that cannot be revealed - the recovery is always a fresh consent.

## Adding an account

1. Store its OAuth app secret in Zoho Vault, category "OAuth App Credential".
2. Add one `EmailIdentity` row to `identities.py` with the Vault password id.
3. `gmail-grant --account <alias> --scopes <set>` for each scope set needed.

No other file changes. If you find yourself editing a second file, something has drifted
from the single source of truth.

## Rules that bite

- **Never print a secret** - not a client secret, refresh token, access token, or revealed
  value; not at INFO, not in an exception message, not in a repr. Output is the identity,
  the scope set, and the outcome.
- **`gmail_secrets.py` is the only module that builds an OAuth flow, runs consent, or
  seals a value.** A second one drifts and then a fix in one leaves the other broken.
- **No credential file belongs in any repo.** If a `credentials.json` or `token*.json`
  appears, something has regressed - grants are sealed at `~/.fnx/gmail/`.
- **A locked Vault must never break a refresh.** Refresh reads the sealed store, which
  carries all four fields the Google client needs. Vault is for consent only.
