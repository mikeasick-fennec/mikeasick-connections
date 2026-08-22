"""Michael's personal-level connection identities.

One row per account this machine can authenticate as. Everything else in the
package resolves through here, so adding an account is one entry, not a sweep.

`alias` is the short name a command line takes. `name` is the durable identity
used for the sealed store filename and for the Vault lookup; it never changes
once grants exist under it. `vault_entry` is the Zoho Vault password id holding
that account's OAuth app secret (category "OAuth App Credential").
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class EmailIdentity:
    alias: str
    name: str
    email: str
    vault_entry: str

    @property
    def login_hint(self) -> str:
        """Pre-fills the Google account picker, and names the Chrome profile."""
        return self.email


EMAIL_IDENTITIES = {
    "personal": EmailIdentity(
        alias="personal",
        name="mike-email-gmail-personal",
        email="mikeasick@gmail.com",
        vault_entry="274997000000081221",
    ),
    "enterprise": EmailIdentity(
        alias="enterprise",
        name="mike-email-gmail-company",
        email="michael.a.sick@serenesoftware.com",
        vault_entry="274997000000081228",
    ),
}

BY_NAME = {i.name: i for i in EMAIL_IDENTITIES.values()}


def resolve(alias_or_name: str) -> EmailIdentity:
    """An identity by alias ("personal") or by durable name."""
    if alias_or_name in EMAIL_IDENTITIES:
        return EMAIL_IDENTITIES[alias_or_name]
    if alias_or_name in BY_NAME:
        return BY_NAME[alias_or_name]
    known = ", ".join(sorted(EMAIL_IDENTITIES))
    raise KeyError(f"unknown identity {alias_or_name!r}; known aliases: {known}")
