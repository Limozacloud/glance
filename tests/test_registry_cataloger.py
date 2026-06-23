"""Tests for the Windows registry cataloger.

winreg is Windows-only, so all catalog tests mock the module via sys.modules.
The matching logic and index loading are tested without platform restrictions.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import patch

import pytest

from glance.catalogers.registry import RegistryCataloger, _fill, _match
from glance.models import ScanReport, Source


# ── helpers ──────────────────────────────────────────────────────────────────


SMALL_INDEX = [
    {
        "id": "chrome",
        "display_name_contains": ["Google Chrome"],
        "publisher_contains": ["Google"],
        "name": "google-chrome",
        "cpe_template": "cpe:2.3:a:google:chrome:{version}:*:*:*:*:*:*:*",
        "purl_template": "pkg:generic/google-chrome@{version}",
    },
    {
        "id": "notepad_plus_plus",
        "display_name_contains": ["Notepad++"],
        "publisher_contains": [],  # no publisher filter
        "name": "notepad-plus-plus",
        "cpe_template": "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:{version}:*:*:*:*:*:*:*",
        "purl_template": "pkg:generic/notepad-plus-plus@{version}",
    },
    {
        "id": "7zip",
        "display_name_contains": ["7-Zip"],
        "publisher_contains": ["Igor Pavlov"],
        "name": "7zip",
        "cpe_template": "cpe:2.3:a:7-zip:7-zip:{version}:*:*:*:*:*:*:*",
        "purl_template": "pkg:generic/7zip@{version}",
    },
]

_HKLM = 0x80000002
_HKCU = 0x80000001


class _FakeRootKey:
    """Simulates the key returned by OpenKey(hive, uninstall_subkey)."""

    def __init__(self, children: dict):
        self._children = list(children)
        self._child_data = children

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class _FakeChildKey:
    """Simulates the key returned by OpenKey(root_key, child_name)."""

    def __init__(self, values: dict):
        self._values = values

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


def _make_winreg(hive_data: dict):
    """Build a fake winreg module from a hive_data dict.

    hive_data: {(hive_int, subkey_str): {child_name: {field: value}}}
    """
    mod = types.ModuleType("winreg")

    def open_key(hive_or_key, subkey):
        if isinstance(hive_or_key, int):
            data = hive_data.get((hive_or_key, subkey))
            if data is None:
                raise OSError("key not found")
            return _FakeRootKey(data)
        if isinstance(hive_or_key, _FakeRootKey):
            data = hive_or_key._child_data.get(subkey)
            if data is None:
                raise OSError("child key not found")
            return _FakeChildKey(data)
        raise OSError("unexpected key type")

    def enum_key(key, index):
        if isinstance(key, _FakeRootKey):
            if index < len(key._children):
                return key._children[index]
        raise OSError("no more subkeys")

    def query_value_ex(key, value_name):
        if isinstance(key, _FakeChildKey):
            val = key._values.get(value_name)
            if val is None:
                raise OSError("value not found")
            return (val, 1)
        raise OSError("not a value key")

    mod.OpenKey = open_key
    mod.EnumKey = enum_key
    mod.QueryValueEx = query_value_ex
    return mod


def _catalog_with(hive_data: dict, index=None) -> tuple[list, ScanReport]:
    """Run RegistryCataloger.catalog() with mocked winreg and optional index."""
    winreg_mock = _make_winreg(hive_data)
    report = ScanReport()
    cat = RegistryCataloger()
    with (
        patch.dict(sys.modules, {"winreg": winreg_mock}),
        patch("glance.catalogers.registry._index", return_value=index or SMALL_INDEX),
        patch.object(cat, "available", return_value=True),
    ):
        comps = cat.catalog(report)
    return comps, report


# ── _match() unit tests ───────────────────────────────────────────────────────


def test_match_display_name_substring():
    entry = SMALL_INDEX[0]  # Google Chrome
    assert _match("Google Chrome", "Google LLC", entry)


def test_match_display_name_case_insensitive():
    entry = SMALL_INDEX[0]
    assert _match("GOOGLE CHROME 124", "Google LLC", entry)


def test_match_no_publisher_filter():
    entry = SMALL_INDEX[1]  # Notepad++ has no publisher filter
    assert _match("Notepad++ (64-bit x64)", "Notepad++ Team", entry)
    assert _match("Notepad++ (64-bit x64)", "AnyPublisher", entry)


def test_match_publisher_filter_blocks():
    entry = SMALL_INDEX[0]  # Chrome requires "Google" in publisher
    assert not _match("Google Chrome", "SomeSpoofPublisher", entry)


def test_match_publisher_filter_case_insensitive():
    entry = SMALL_INDEX[2]  # 7-Zip requires "Igor Pavlov"
    assert _match("7-Zip 24.08 (x64)", "igor pavlov", entry)


def test_no_match_unrelated_software():
    entry = SMALL_INDEX[0]
    assert not _match("AcmeCorp Internal Tool", "AcmeCorp", entry)


# ── _fill() unit tests ────────────────────────────────────────────────────────


def test_fill_substitutes_version():
    tmpl = "pkg:generic/google-chrome@{version}"
    assert _fill(tmpl, "124.0.0") == "pkg:generic/google-chrome@124.0.0"


def test_fill_empty_version_becomes_wildcard():
    tmpl = "cpe:2.3:a:google:chrome:{version}:*"
    assert _fill(tmpl, "") == "cpe:2.3:a:google:chrome:*:*"


# ── index loading ─────────────────────────────────────────────────────────────


def test_real_index_loads():
    from glance.catalogers.registry import _load_index
    entries = _load_index()
    assert len(entries) > 10
    ids = {e["id"] for e in entries}
    assert "crowdstrike_falcon" in ids
    assert "notepad_plus_plus" in ids
    assert "google_chrome" in ids
    for e in entries:
        assert "display_name_contains" in e
        assert "cpe_template" in e
        assert "purl_template" in e


# ── catalog() with mocked winreg ─────────────────────────────────────────────


HKLM_UNINSTALL = (
    _HKLM,
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
)
HKLM_WOW = (
    _HKLM,
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
)
HKCU_UNINSTALL = (
    _HKCU,
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
)


def test_catalog_matched_component():
    hive_data = {
        HKLM_UNINSTALL: {
            "{chrome}": {
                "DisplayName": "Google Chrome",
                "Publisher": "Google LLC",
                "DisplayVersion": "124.0.6367.92",
            }
        }
    }
    comps, report = _catalog_with(hive_data)
    assert len(comps) == 1
    c = comps[0]
    assert c.name == "google-chrome"
    assert c.version == "124.0.6367.92"
    assert c.purl == "pkg:generic/google-chrome@124.0.6367.92"
    assert c.cpes == ["cpe:2.3:a:google:chrome:124.0.6367.92:*:*:*:*:*:*:*"]
    assert c.source == Source.REGISTRY
    assert c.managed is True
    assert c.metadata["display_name"] == "Google Chrome"


def test_catalog_no_match_skipped():
    hive_data = {
        HKLM_UNINSTALL: {
            "{acme}": {
                "DisplayName": "AcmeCorp Internal Tool v3",
                "Publisher": "AcmeCorp",
                "DisplayVersion": "3.0.0",
            }
        }
    }
    comps, _ = _catalog_with(hive_data)
    assert comps == []


def test_catalog_missing_display_name_skipped():
    hive_data = {
        HKLM_UNINSTALL: {
            "{nodisplay}": {
                "Publisher": "Google LLC",
                "DisplayVersion": "1.0",
                # no DisplayName
            }
        }
    }
    comps, _ = _catalog_with(hive_data)
    assert comps == []


def test_catalog_missing_version_yields_none():
    hive_data = {
        HKLM_UNINSTALL: {
            "{notepad}": {
                "DisplayName": "Notepad++ (64-bit x64)",
                "Publisher": "Notepad++ Team",
                # no DisplayVersion
            }
        }
    }
    comps, _ = _catalog_with(hive_data)
    assert len(comps) == 1
    assert comps[0].version is None
    assert comps[0].purl == "pkg:generic/notepad-plus-plus@*"


def test_catalog_deduplicates_across_hives():
    """Same DisplayName+Version in HKLM and WOW6432 → one component."""
    entry = {
        "DisplayName": "7-Zip 24.08 (x64)",
        "Publisher": "Igor Pavlov",
        "DisplayVersion": "24.08",
    }
    hive_data = {
        HKLM_UNINSTALL: {"{7zip64}": entry},
        HKLM_WOW: {"{7zip32}": entry},
    }
    comps, _ = _catalog_with(hive_data)
    assert len(comps) == 1


def test_catalog_different_versions_not_deduplicated():
    hive_data = {
        HKLM_UNINSTALL: {
            "{npp1}": {
                "DisplayName": "Notepad++",
                "Publisher": "Notepad++ Team",
                "DisplayVersion": "8.7.4",
            }
        },
        HKCU_UNINSTALL: {
            "{npp2}": {
                "DisplayName": "Notepad++",
                "Publisher": "Notepad++ Team",
                "DisplayVersion": "8.6.0",
            }
        },
    }
    comps, _ = _catalog_with(hive_data)
    assert len(comps) == 2


def test_catalog_first_match_wins():
    """An entry only maps to the first matching index rule, not all of them."""
    # "Google Chrome" matches the chrome entry → only one component
    hive_data = {
        HKLM_UNINSTALL: {
            "{chrome}": {
                "DisplayName": "Google Chrome",
                "Publisher": "Google LLC",
                "DisplayVersion": "124.0",
            }
        }
    }
    comps, _ = _catalog_with(hive_data)
    assert len(comps) == 1
    assert comps[0].name == "google-chrome"


def test_catalog_status_recorded():
    hive_data = {HKLM_UNINSTALL: {}}
    _, report = _catalog_with(hive_data)
    status = report.catalogers[-1]
    assert status.name == "registry"
    assert status.ran is True


def test_catalog_inaccessible_hive_skipped():
    """A hive that raises OSError on OpenKey should be silently skipped."""
    hive_data = {
        # only HKCU present; HKLM will raise OSError
        HKCU_UNINSTALL: {
            "{chrome}": {
                "DisplayName": "Google Chrome",
                "Publisher": "Google LLC",
                "DisplayVersion": "124.0",
            }
        }
    }
    comps, _ = _catalog_with(hive_data)
    assert len(comps) == 1


# ── platform guard ────────────────────────────────────────────────────────────


def test_unavailable_on_non_windows():
    cat = RegistryCataloger()
    with patch.object(sys, "platform", "linux"):
        assert not cat.available()
        report = ScanReport()
        comps = cat.catalog(report)
    assert comps == []
    assert report.catalogers[-1].ran is False


def test_file_index_always_empty():
    assert RegistryCataloger().file_index() == {}
