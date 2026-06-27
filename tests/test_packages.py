from __future__ import annotations

import subprocess

from glance.catalogers import rpm as rpm_mod
from glance.catalogers.apk import ApkCataloger
from glance.catalogers.dpkg import DpkgCataloger
from glance.catalogers.rpm import RpmCataloger
from glance.models import ScanReport

DPKG_STATUS = """\
Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit

Package: removed-pkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0.0

Package: libssl3
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1~deb12u2
"""


def _make_dpkg_root(tmp_path):
    root = tmp_path / "root"
    info = root / "var/lib/dpkg/info"
    info.mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text(DPKG_STATUS, encoding="utf-8")
    (info / "libssl3.list").write_text(
        "/.\n/usr/lib/x86_64-linux-gnu/libssl.so.3\n/usr/lib/x86_64-linux-gnu/libcrypto.so.3\n",
        encoding="utf-8",
    )
    return str(root)


def test_dpkg_parses_installed_only(tmp_path):
    cat = DpkgCataloger(root=_make_dpkg_root(tmp_path))
    assert cat.available()
    report = ScanReport()
    comps = cat.catalog(report)
    names = {c.name for c in comps}
    assert names == {"openssl", "libssl3"}  # deinstalled one excluded
    openssl = next(c for c in comps if c.name == "openssl")
    assert openssl.purl.startswith("pkg:deb/")
    assert "3.0.11-1~deb12u2" in openssl.purl
    assert openssl.managed is True


def test_dpkg_file_index_maps_paths(tmp_path):
    cat = DpkgCataloger(root=_make_dpkg_root(tmp_path))
    cat.catalog(ScanReport())
    index = cat.file_index()
    assert "/usr/lib/x86_64-linux-gnu/libssl.so.3" in index
    assert index["/usr/lib/x86_64-linux-gnu/libcrypto.so.3"].startswith("pkg:deb/")


APK_DB = """\
P:openssl
V:3.1.4-r5
A:x86_64
F:usr/lib
R:libcrypto.so.3
R:libssl.so.3

P:musl
V:1.2.4-r2
A:x86_64
F:lib
R:libc.musl-x86_64.so.1
"""


def test_apk_parses_and_indexes(tmp_path):
    root = tmp_path / "root"
    (root / "lib/apk/db").mkdir(parents=True)
    (root / "lib/apk/db/installed").write_text(APK_DB, encoding="utf-8")
    cat = ApkCataloger(root=str(root))
    assert cat.available()
    comps = cat.catalog(ScanReport())
    assert {c.name for c in comps} == {"openssl", "musl"}
    index = cat.file_index()
    assert index["/usr/lib/libcrypto.so.3"].startswith("pkg:apk/")
    assert "/lib/libc.musl-x86_64.so.1" in index


def test_rpm_catalog_mocked(monkeypatch):
    cat = RpmCataloger()
    cat.rpm = "/usr/bin/rpm"

    def fake_run(cmd, **kwargs):
        out = (
            "openssl-libs\t1\t3.0.7\t1.el9\tx86_64\topenssl-3.0.7-1.el9.src.rpm\n"
            "zlib\t(none)\t1.2.11\t40.el9\tx86_64\tzlib-1.2.11-40.el9.src.rpm\n"
        )
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(rpm_mod.subprocess, "run", fake_run)
    comps = cat.catalog(ScanReport())
    assert {c.name for c in comps} == {"openssl-libs", "zlib"}
    ol = next(c for c in comps if c.name == "openssl-libs")
    assert ol.version == "3.0.7-1.el9"
    assert ol.purl.startswith("pkg:rpm/")
    assert "epoch=1" in ol.purl
    assert "upstream=openssl" in ol.purl


def test_rpm_owner_mocked(monkeypatch):
    cat = RpmCataloger()
    cat.rpm = "/usr/bin/rpm"

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="openssl-libs\t1\t3.0.7\t1.el9\tx86_64\topenssl-3.0.7-1.el9.src.rpm\n",
            stderr="",
        )

    monkeypatch.setattr(rpm_mod.subprocess, "run", fake_run)
    owner = cat.owner("/usr/lib64/libcrypto.so.3")
    assert owner and owner.startswith("pkg:rpm/")
    # cached on second call
    assert cat.owner("/usr/lib64/libcrypto.so.3") == owner


def test_rpm_unavailable_records_status(monkeypatch):
    cat = RpmCataloger()
    cat.rpm = None
    report = ScanReport()
    assert cat.catalog(report) == []
    assert report.catalogers[-1].ran is False
