# Adopting mikeasick-connections in a project

What a consuming project has to do. Install and API are in `README.md`; accounts,
grants, Vault, and new-machine setup are in `.claude/skills/personal-connections/`.

## Pin it

```
mikeasick-connections @ git+https://github.com/mikeasick-fennec/mikeasick-connections@main
```

In the project's `requirements.txt`. Never a path or `-e` install: that makes the project
depend on whatever is uncommitted in one working tree.

## Replace existing Gmail code with a shim

Do not edit every caller. Turn the project's own module into a re-export:

```python
"""Thin re-export of mikeasick_connections.gmail_auth. Add nothing here."""

from mikeasick_connections.gmail_auth import (  # noqa: F401
    ACCOUNTS, GMAIL_SCOPES, GMAIL_MODIFY_SCOPES, CALENDAR_SCOPES,
    get_all_services, get_all_calendar_services, get_gmail_service,
    get_modify_service, has_modify_token, identity_for,
)
```

Then delete the project's credential paths, consent flow, and token writes. Validate live
through the shim *before* deleting, not after.

## Guard against a second copy

The failure this package prevents is a project quietly growing its own flow again. One
structural test holds the line: AST-walk the project's source, fail on any file calling
`from_authorized_user_file`, `from_client_secrets_file`, or `run_local_server`, or naming
a plaintext Gmail token file. Working copy:
`mikeasick-hunt/scanner/tests/test_gmail_oauth_single_chokepoint.py`.

Prove it fires before trusting it -- add a `run_local_server` call, watch it go red, take
it out.

## One API note worth knowing early

`get_all_services()` returns only accounts holding a sealed grant, so a missing grant is a
missing key rather than an exception mid-run. Gate on `has_modify_token(alias)` before
reaching for modify scope: without a grant, that call opens an interactive consent, which
will hang a batch job.
