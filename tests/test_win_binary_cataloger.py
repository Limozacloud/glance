"""Tests for the Windows PE binary cataloger (WinBinaryCataloger).

All FS / VERSIONINFO interaction is mocked so tests run on any platform.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from glance.catalogers.win_binary import (
    WinBinaryCataloger,
    _normalize_version,
    match_binary,
)
from glance.models import ComponentType, ScanReport, Source


# ── Small test index ──────────────────────────────────────────────────────────

SMALL_INDEX = [
    {
        "id": "openssl",
        "product_name_contains": ["OpenSSL"],
        "company_contains": ["OpenSSL"],
        "name": "openssl",
        "cpe_template": "cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*",
        "purl_template": "pkg:generic/openssl@{version}",
    },
    {
        "id": "curl",
        "product_name_contains": ["curl", "libcurl"],
        "company_contains": ["curl", "Daniel Stenberg"],
        "name": "curl",
        "cpe_template": "cpe:2.3:a:haxx:curl:{version}:*:*:*:*:*:*:*",
        "purl_template": "pkg:generic/curl@{version}",
    },
    {
        "id": "zlib",
        "product_name_contains": ["zlib"],
        "company_contains": [],  # no company filter
        "name": "zlib",
        "cpe_template": "cpe:2.3:a:zlib:zlib:{version}:*:*:*:*:*:*:*",
        "purl_template": "pkg:generic/zlib@{version}",
    },
]


# ── _normalize_version ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("3.0.13.0", "3.0.13"),         # 4-part trailing .0 stripped
        ("1.2.3.4", "1.2.3.4"),         # 4-part, non-zero last → kept
        ("8.7", "8.7"),                  # 2-part → unchanged
        ("1.64.0.0 (MSVC release)", "1.64.0"),  # suffix stripped, then trailing .0
        ("2.48.1.windows.1", "2.48.1"), # non-numeric after first break
        ("1.0.0.0", "1.0.0"),           # trailing .0 stripped
        ("", ""),                        # empty → empty
    ],
)
def test_normalize_version(raw, expected):
    assert _normalize_version(raw) == expected


# ── match_binary ──────────────────────────────────────────────────────────────


def test_match_by_product_name():
    entry = SMALL_INDEX[0]  # openssl
    assert match_binary("The OpenSSL Toolkit", "The OpenSSL Project", entry)


def test_match_product_name_case_insensitive():
    assert match_binary("OPENSSL shared library", "the openssl project", SMALL_INDEX[0])


def test_match_no_company_filter():
    entry = SMALL_INDEX[2]  # zlib — empty company_contains
    assert match_binary("zlib data compression library", "anyone", entry)
    assert match_binary("zlib data compression library", "", entry)


def test_match_company_blocks_wrong_company():
    entry = SMALL_INDEX[0]  # openssl requires company containing "OpenSSL"
    assert not match_binary("OpenSSL", "AcmeCorp", entry)


def test_match_fails_unrelated():
    assert not match_binary("AcmeAgent", "AcmeCorp", SMALL_INDEX[0])


# ── index loading ─────────────────────────────────────────────────────────────


def test_real_binary_index_loads():
    from glance.catalogers.win_binary import _load_binary_index
    entries = _load_binary_index()
    assert len(entries) >= 10
    ids = {e["id"] for e in entries}
    assert "openssl" in ids
    assert "curl" in ids
    assert "python_runtime" in ids
    for e in entries:
        assert "product_name_contains" in e
        assert "cpe_template" in e
        assert "purl_template" in e


# ── _is_pe ────────────────────────────────────────────────────────────────────


def test_is_pe_true(tmp_path):
    from glance.catalogers.win_binary import _is_pe
    f = tmp_path / "test.dll"
    f.write_bytes(b"MZ" + b"\x00" * 100)
    assert _is_pe(str(f))


def test_is_pe_false_wrong_magic(tmp_path):
    from glance.catalogers.win_binary import _is_pe
    f = tmp_path / "test.dll"
    f.write_bytes(b"\x7fELF" + b"\x00" * 100)
    assert not _is_pe(str(f))


def test_is_pe_false_missing_file():
    from glance.catalogers.win_binary import _is_pe
    assert not _is_pe("/does/not/exist.dll")


# ── catalog() with mocked filesystem / VERSIONINFO ───────────────────────────


def _make_fake_tree(tmp_path: Path, files: dict[str, dict]) -> str:
    """Write fake PE files and return the root directory path.

    files: {relative_path: versioninfo_dict or None (non-PE)}
    """
    root = tmp_path / "pfx"
    for rel, info in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if info is not None:
            p.write_bytes(b"MZ" + b"\x00" * 64)  # fake PE
        else:
            p.write_bytes(b"\x7fELF" + b"\x00" * 64)  # not a PE
    return str(root)


def _catalog(tmp_path: Path, tree: dict[str, dict | None], index=None) -> tuple[list, ScanReport]:
    root = _make_fake_tree(tmp_path, tree)

    def fake_versioninfo(path: str) -> dict:
        rel = os.path.relpath(path, root).replace("\\", "/")
        return tree.get(rel) or tree.get(os.path.relpath(path, root)) or {}

    report = ScanReport()
    cat = WinBinaryCataloger(paths=[root])
    with (
        patch("glance.catalogers.win_binary.read_versioninfo", side_effect=fake_versioninfo),
        patch("glance.catalogers.win_binary._binary_index", return_value=index or SMALL_INDEX),
        patch.object(cat, "available", return_value=True),
    ):
        comps = cat.catalog(report)
    return comps, report


def test_catalog_matched_dll(tmp_path):
    tree = {
        "vendor/libssl-3.dll": {
            "ProductName": "The OpenSSL Toolkit",
            "ProductVersion": "3.2.4.0",
            "CompanyName": "The OpenSSL Project, https://www.openssl.org/",
        }
    }
    comps, report = _catalog(tmp_path, tree)
    assert len(comps) == 1
    c = comps[0]
    assert c.name == "openssl"
    assert c.version == "3.2.4"
    assert c.purl == "pkg:generic/openssl@3.2.4"
    assert c.cpes == ["cpe:2.3:a:openssl:openssl:3.2.4:*:*:*:*:*:*:*"]
    assert c.source == Source.BINARY
    assert c.type == ComponentType.LIBRARY
    assert c.managed is False


def test_catalog_non_pe_skipped(tmp_path):
    tree = {
        "vendor/libssl-3.dll": None  # ELF magic, not PE
    }
    comps, _ = _catalog(tmp_path, tree)
    assert comps == []


def test_catalog_no_versioninfo_skipped(tmp_path):
    tree = {
        "vendor/libssl-3.dll": {}  # PE but empty VERSIONINFO
    }
    comps, _ = _catalog(tmp_path, tree)
    assert comps == []


def test_catalog_no_product_name_skipped(tmp_path):
    tree = {
        "vendor/libssl-3.dll": {
            "CompanyName": "The OpenSSL Project",
            "ProductVersion": "3.2.4",
            # no ProductName
        }
    }
    comps, _ = _catalog(tmp_path, tree)
    assert comps == []


def test_catalog_no_match_skipped(tmp_path):
    tree = {
        "vendor/acme.dll": {
            "ProductName": "AcmeCorp Internal Library",
            "CompanyName": "AcmeCorp",
            "ProductVersion": "1.0.0",
        }
    }
    comps, _ = _catalog(tmp_path, tree)
    assert comps == []


def test_catalog_extension_gate(tmp_path):
    """Files without .dll/.exe/.sys extension must be ignored even if they are PE."""
    tree = {
        "vendor/openssl.lib": {  # wrong extension
            "ProductName": "OpenSSL",
            "CompanyName": "The OpenSSL Project",
            "ProductVersion": "3.2.4",
        }
    }
    comps, _ = _catalog(tmp_path, tree)
    assert comps == []


def test_catalog_deduplicates_same_version(tmp_path):
    """Same product + version found in two DLLs → one component."""
    info = {
        "ProductName": "The OpenSSL Toolkit",
        "CompanyName": "The OpenSSL Project",
        "ProductVersion": "3.2.4",
    }
    tree = {
        "app1/libssl-3.dll": info,
        "app2/libssl-3.dll": info,
    }
    comps, _ = _catalog(tmp_path, tree)
    assert len(comps) == 1


def test_catalog_different_versions_not_deduplicated(tmp_path):
    tree = {
        "app1/libssl-3.dll": {
            "ProductName": "The OpenSSL Toolkit",
            "CompanyName": "The OpenSSL Project",
            "ProductVersion": "3.0.13",
        },
        "app2/libssl-3.dll": {
            "ProductName": "The OpenSSL Toolkit",
            "CompanyName": "The OpenSSL Project",
            "ProductVersion": "3.2.4",
        },
    }
    comps, _ = _catalog(tmp_path, tree)
    assert len(comps) == 2
    versions = {c.version for c in comps}
    assert versions == {"3.0.13", "3.2.4"}


def test_catalog_version_fallback_to_file_version(tmp_path):
    tree = {
        "vendor/curl.dll": {
            "ProductName": "curl",
            "CompanyName": "curl, https://curl.se",
            # no ProductVersion — should fall back to FileVersion
            "FileVersion": "8.12.1.0",
        }
    }
    comps, _ = _catalog(tmp_path, tree)
    assert len(comps) == 1
    assert comps[0].version == "8.12.1"


def test_catalog_missing_version_yields_none(tmp_path):
    tree = {
        "vendor/zlib1.dll": {
            "ProductName": "zlib data compression",
            "CompanyName": "zlib",
        }
    }
    comps, _ = _catalog(tmp_path, tree)
    assert len(comps) == 1
    assert comps[0].version is None
    assert comps[0].purl == "pkg:generic/zlib@*"


def test_catalog_status_recorded(tmp_path):
    comps, report = _catalog(tmp_path, {})
    status = report.catalogers[-1]
    assert status.name == "win_binary"
    assert status.ran is True
    assert status.components_found == 0


def test_catalog_missing_root_dir_skipped(tmp_path):
    """A configured path that does not exist must be skipped silently."""
    report = ScanReport()
    cat = WinBinaryCataloger(paths=[str(tmp_path / "nonexistent")])
    with (
        patch("glance.catalogers.win_binary._binary_index", return_value=SMALL_INDEX),
        patch.object(cat, "available", return_value=True),
    ):
        comps = cat.catalog(report)
    assert comps == []
    assert report.catalogers[-1].ran is True


# ── platform guard ────────────────────────────────────────────────────────────


def test_unavailable_on_non_windows():
    import sys
    cat = WinBinaryCataloger()
    with patch.object(sys, "platform", "linux"):
        assert not cat.available()
        report = ScanReport()
        comps = cat.catalog(report)
    assert comps == []
    assert report.catalogers[-1].ran is False


def test_file_index_always_empty():
    assert WinBinaryCataloger().file_index() == {}
