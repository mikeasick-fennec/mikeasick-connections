"""Open a URL in a named profile of the operator's own Chrome.

Chrome identifies a profile on the command line by its DIRECTORY name
(`--profile-directory="Profile 4"`), which is not what a human knows. The map
from directory to signed-in account lives in
`<User Data>/Local State` -> `profile.info_cache[<dir>].user_name`.

Why this matters: anything that hands a URL to the default browser lands in
whichever profile is default, signed in as whatever account that is. For an
OAuth consent screen that is the wrong account, and `login_hint` only pre-fills
the picker -- it does not switch the session.

    from mikeasick_connections import chrome_profiles
    chrome_profiles.open_url(url, account="mikeasick@gmail.com")

For a library that opens the browser itself (google-auth-oauthlib's
`run_local_server(browser=...)`), register a controller and pass its name:

    name = chrome_profiles.register_opener(account="mikeasick@gmail.com")
    flow.run_local_server(port=0, browser=name)

This drives the operator's real Chrome, with its real profiles. A tool that
runs its own `--user-data-dir` (a scraper persona, say) is a different thing and
does not belong here.
"""

import json
import webbrowser
from pathlib import Path

CHROME_EXE = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")

USER_DATA_DIR = Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data"


class ProfileNotFound(Exception):
    """No Chrome profile directory matches the requested account."""


def profiles(user_data_dir: Path | None = None) -> dict[str, str]:
    """{profile directory: signed-in account email}. Empty string when signed out."""
    root = user_data_dir or USER_DATA_DIR
    state = root / "Local State"
    if not state.is_file():
        return {}
    try:
        cache = json.loads(state.read_text(encoding="utf-8"))["profile"]["info_cache"]
    except (OSError, KeyError, json.JSONDecodeError):
        return {}
    return {d: (info.get("user_name") or "") for d, info in sorted(cache.items())}


def resolve(account: str, user_data_dir: Path | None = None) -> str:
    """The profile directory signed in as `account`. Case-insensitive.

    Accepts a directory name directly, so a caller can pin "Profile 4" when the
    profile is signed out and has no email to match on.
    """
    found = profiles(user_data_dir)
    if account in found:
        return account
    wanted = account.strip().lower()
    for directory, email in found.items():
        if email.lower() == wanted:
            return directory
    known = ", ".join(f"{d}={e or '(signed out)'}" for d, e in found.items()) or "none"
    raise ProfileNotFound(f"no Chrome profile for {account!r}; profiles: {known}")


def _controller(directory: str) -> webbrowser.GenericBrowser:
    if not CHROME_EXE.is_file():
        raise ProfileNotFound(f"chrome.exe not found at {CHROME_EXE}")
    chrome = CHROME_EXE
    # GenericBrowser substitutes the URL for "%s".
    return webbrowser.GenericBrowser(
        [str(chrome), f"--profile-directory={directory}", "%s"])


def register_opener(account: str, user_data_dir: Path | None = None) -> str:
    """Register a webbrowser controller for `account` and return its name.

    Pass the name to any API that takes a `webbrowser` name, e.g.
    `flow.run_local_server(browser=<name>)`.
    """
    directory = resolve(account, user_data_dir)
    name = f"chrome-profile-{directory.replace(' ', '-').lower()}"
    webbrowser.register(name, None, _controller(directory), preferred=False)
    return name


def open_url(url: str, *, account: str, user_data_dir: Path | None = None) -> str:
    """Open `url` in the Chrome profile signed in as `account`."""
    directory = resolve(account, user_data_dir)
    _controller(directory).open(url, new=1, autoraise=True)
    return directory
