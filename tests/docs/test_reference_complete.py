"""The reference pages must cover every setting and every system check.

The lists come from the source, so adding a setting or a check without
documenting it fails CI.
"""

import re
from pathlib import Path

import pytest

from django_signet.conf import DEFAULTS

ROOT = Path(__file__).resolve().parents[2]
SETTINGS_PAGE = ROOT / "docs" / "reference" / "settings.md"
CHECKS_PAGE = ROOT / "docs" / "reference" / "checks.md"
CHECK_IDS = sorted(
    {
        check_id
        for module in (ROOT / "src" / "django_signet" / "checks").glob("*.py")
        for check_id in re.findall(r"signet\.[EW]\d{3}", module.read_text())
    }
)


@pytest.mark.parametrize("key", sorted(DEFAULTS))
def test_every_setting_is_documented(key):
    assert f"`{key}`" in SETTINGS_PAGE.read_text(), (
        f"{key} missing from {SETTINGS_PAGE.name}"
    )


@pytest.mark.parametrize("check_id", CHECK_IDS)
def test_every_system_check_is_documented(check_id):
    assert f"`{check_id}`" in CHECKS_PAGE.read_text(), (
        f"{check_id} missing from {CHECKS_PAGE.name}"
    )


def test_the_check_list_is_not_empty():
    """Guards the regex itself: an empty list would make the test above vacuous."""
    assert len(CHECK_IDS) >= 10
