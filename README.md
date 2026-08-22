# mikeasick-connections

Michael's personal-level connections: the accounts he authenticates as, and the code
that obtains and holds those grants.

Two Gmail accounts, three scope sets each. The OAuth app secret lives in Zoho Vault and
is read in memory only when a fresh consent runs. Grants are sealed with Windows DPAPI at
`~/.fnx/gmail/<identity>.json`, outside every repository. No credential file lives here.

## Install

```
pip install "git+https://github.com/mikeasick-fennec/mikeasick-connections@main"
```

Consumers install from `origin/main`, never a path or editable install -- otherwise every
project depends on whatever happens to be uncommitted in one working tree.

## Use

```python
from mikeasick_connections import gmail_auth

services = gmail_auth.get_all_services()          # {alias: gmail service}
svc = gmail_auth.get_modify_service("personal")   # label / draft / send
```

```
gmail-check --account personal --scopes all       # is the grant live? no Vault needed
gmail-grant --account personal --scopes gmail     # obtain one; needs an unlocked Vault
```

`CLAUDE.md` carries the boundary and the rules. `.claude/skills/personal-connections/`
is the operator guide. `ADOPTING.md` is what a consuming project has to do.

## Develop

```
py -3.12 -m venv .venv && .venv/Scripts/python -m pip install -e . pytest
.venv/Scripts/python -m pytest
```

This is the only place an editable install belongs.
