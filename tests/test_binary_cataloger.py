from __future__ import annotations

import os

from glance.catalogers.binary import BinaryCataloger
from glance.config import Config
from glance.models import ScanReport, SkipReason

OPENSSL_BLOB = (
    b"\x7fELF\x02\x01\x01" + b"\x00" * 64 + b"\x00OpenSSL 1.1.1w  11 Sep 2023\x00" + b"\x00" * 16
)


def _write(path: str, data: bytes) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def test_extracts_openssl_with_purl_and_cpe(tmp_path):
    p = _write(str(tmp_path / "opt/agent/lib/libcrypto.so.1.1"), OPENSSL_BLOB)
    comps = BinaryCataloger().catalog({p}, Config(), ScanReport())
    assert len(comps) == 1
    c = comps[0]
    assert (c.name, c.version) == ("openssl", "1.1.1w")
    assert c.purl == "pkg:generic/openssl@1.1.1w"
    assert c.cpes == ["cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"]


def test_libssl_and_libcrypto_merge_into_one_component(tmp_path):
    a = _write(str(tmp_path / "opt/agent/lib/libcrypto.so.1.1"), OPENSSL_BLOB)
    b = _write(str(tmp_path / "opt/agent/lib/libssl.so.1.1"), OPENSSL_BLOB)
    comps = BinaryCataloger().catalog({a, b}, Config(), ScanReport())
    # same name+version -> one component with two occurrences (primary vs supporting)
    assert len(comps) == 1
    paths = {occ.path for occ in comps[0].occurrences}
    assert paths == {a, b}


def test_max_file_size_skips_and_reports(tmp_path):
    p = _write(str(tmp_path / "usr/bin/openssl"), OPENSSL_BLOB)
    report = ScanReport()
    comps = BinaryCataloger().catalog({p}, Config(max_file_size=8), report)
    assert comps == []
    assert any(s.reason == SkipReason.MAX_FILE_SIZE for s in report.skipped)


def test_elf_precheck_skips_non_elf_when_enabled(tmp_path):
    # a script-style "openssl" with no ELF magic
    p = _write(str(tmp_path / "usr/bin/openssl"), b"\x00OpenSSL 3.0.13 \x00")
    report = ScanReport()
    comps = BinaryCataloger().catalog({p}, Config(elf_precheck=True), report)
    assert comps == []
    assert any(s.reason == SkipReason.NOT_ELF for s in report.skipped)
    # but with precheck off (default) it is found
    comps2 = BinaryCataloger().catalog({p}, Config(elf_precheck=False), ScanReport())
    assert comps2 and comps2[0].version == "3.0.13"


def test_sha256_optional(tmp_path):
    p = _write(str(tmp_path / "opt/x/libcrypto.so.3"), OPENSSL_BLOB)
    comps = BinaryCataloger().catalog({p}, Config(compute_sha256=True), ScanReport())
    assert comps[0].occurrences[0].sha256 is not None
    comps2 = BinaryCataloger().catalog({p}, Config(compute_sha256=False), ScanReport())
    assert comps2[0].occurrences[0].sha256 is None


def test_files_read_counter(tmp_path):
    p = _write(str(tmp_path / "opt/x/libcrypto.so.3"), OPENSSL_BLOB)
    report = ScanReport()
    BinaryCataloger().catalog({p}, Config(), report)
    assert report.files_read == 1
