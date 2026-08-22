"""Chrome profile directory <-> account resolution.

Fails when absent: consent lands in whichever profile is default, signed in as
the wrong Google account, and `login_hint` only pre-fills the picker.
"""

import json

import pytest

from mikeasick_connections import chrome_profiles

CACHE = {
    "profile": {"info_cache": {
        "Default": {"user_name": "work@example.com", "name": "work"},
        "Profile 1": {"name": "signed out"},
        "Profile 4": {"user_name": "Personal@Example.com", "name": "me"},
    }}
}


@pytest.fixture
def user_data(tmp_path):
    (tmp_path / "Local State").write_text(json.dumps(CACHE), encoding="utf-8")
    return tmp_path


def test_profiles_maps_directory_to_account(user_data):
    assert chrome_profiles.profiles(user_data) == {
        "Default": "work@example.com",
        "Profile 1": "",
        "Profile 4": "Personal@Example.com",
    }


def test_resolve_matches_account_case_insensitively(user_data):
    assert chrome_profiles.resolve("personal@example.com", user_data) == "Profile 4"
    assert chrome_profiles.resolve("work@example.com", user_data) == "Default"


def test_resolve_accepts_a_directory_name(user_data):
    """A signed-out profile has no email, so the directory is the only handle."""
    assert chrome_profiles.resolve("Profile 1", user_data) == "Profile 1"


def test_unknown_account_lists_what_exists(user_data):
    with pytest.raises(chrome_profiles.ProfileNotFound) as caught:
        chrome_profiles.resolve("nobody@example.com", user_data)
    message = str(caught.value)
    assert "nobody@example.com" in message
    assert "Profile 4=Personal@Example.com" in message
    assert "Profile 1=(signed out)" in message


def test_missing_local_state_is_empty_not_a_crash(tmp_path):
    assert chrome_profiles.profiles(tmp_path) == {}
