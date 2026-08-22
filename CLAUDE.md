# mikeasick-connections

Michael's **personal-level** connections: the accounts he authenticates as, and the
code that obtains and holds those grants. Not an enterprise capability, deliberately.

code-quality-gates: compliant
tier: script
duplication-baseline: 0.00

Baseline measured 2026-08-22 with `npx jscpd . --min-lines 6 --mode weak`: 0 clones,
0 duplicated lines over 891 python lines. Standard: `~/.claude/docs/CODE-QUALITY-GATES.md`.
The gitleaks secret scan runs on every commit via `githooks/pre-commit`, armed with
`git config core.hooksPath githooks`.

## What this is, and what it is not

**Is:** one small installable package, shared across Michael's local projects, holding the
connection logic that every project would otherwise copy.

**Consumers install from `origin/main` only.** Never a path install, never an editable
install of a working tree:

    pip install "git+https://github.com/mikeasick-fennec/mikeasick-connections@main"

A path install makes every consuming project depend on whatever is uncommitted in this
directory at that moment, which is the copy-paste problem wearing a different hat. Pinning
to `main` means a change reaches consumers when it is committed and pushed, and every
project is running the same thing. Development in THIS repo uses an editable install of
its own venv; that is the only place `-e` belongs.

**Is not:** an `fnx-*` plugin. There is no marketplace entry, no channel, and no record
in `installed_plugins.json`. What makes an fnx plugin an enterprise capability is
publication, not location -- so a path install is the boundary. If a capability here ever
needs to reach another person or another machine's user account, that is the moment to
promote it to a real plugin, not a moment to copy files.

**Consumes fnx-setup, does not publish through it.** `rest_protect` (the DPAPI seal) and
`atomic_write_json` are resolved from `installed_plugins.json` `installPath`, per the
fnx-core plugin contract. Never path math on `__file__`: those plugins are versioned
independently and the cache is `<plugin>/<version>/`.

## Connections held here

| Alias | Identity | Account | Vault entry |
|---|---|---|---|
| `personal` | `mike-email-gmail-personal` | mikeasick@gmail.com | `gmail-personal` |
| `enterprise` | `mike-email-gmail-company` | michael.a.sick@serenesoftware.com | `gmail-serene` |

Both are Google OAuth: Gmail readonly, Gmail modify, and Calendar readonly.
`src/mikeasick_connections/identities.py` is the single source of truth; adding an account
is one entry there.

## Where secrets live

- **App secret** -- Zoho Vault, read in memory only when a fresh consent runs. Never on disk.
- **Grants** -- `~/.fnx/gmail/<identity>.json`, outside every repo. Client id and token
  endpoint plain; client secret and refresh token sealed with Windows DPAPI. No access
  token is stored.
- **Nothing in this repo.** No `credentials.json`, no `token*.json`, ever.

An ordinary refresh reads the sealed store and never touches Vault, so a locked Vault does
not break an unattended run. Vault is consulted only for a first consent.

## A new machine

The sealed store does not travel: DPAPI binds it to this Windows user on this machine.
That is the property that makes the file useless to anything else, not a gap.

On a new machine: install from `origin/main`, unlock Vault, run the grant, approve in the
browser. The app secret comes from Vault; the refresh token comes from Google. Nothing is
copied, and no sealed file moves between machines.

## Commands

    gmail-grant --account personal --scopes gmail      # first grant, needs unlocked Vault
    gmail-grant --list-profiles                        # Chrome profile -> account map
    gmail-check --account personal --scopes all        # is the grant live? no Vault needed

Both come from the installed package, so a consuming project gets them by installing it --
there is nothing to copy and no path to wire up.

Consent is pinned to the Chrome profile signed in as that account. The default browser is
whichever account its profile holds, and `login_hint` only pre-fills the picker.

## Rules

1. **One module builds the OAuth flow**: `gmail_secrets.py`. Nothing else constructs a
   flow, runs consent, or seals a value. Callers use `gmail_auth`.
2. **Never print a secret** -- not at INFO, not in an exception message, not in a repr.
   Operator-facing output is the identity, the scope set, and the outcome.
3. **Never run `zv login` or `zv unlock` in an agent shell** -- the master password enters
   the transcript. Use the `fnx-core:zoho-vault` helper scripts.
4. **Deleting a grant is a fresh consent to recover.** Prove the sealed path works with the
   old files unreachable before removing anything.
