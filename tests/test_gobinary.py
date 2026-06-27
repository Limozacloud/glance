from __future__ import annotations

import mmap

from glance.catalogers.gobinary import GoBinaryCataloger, _is_elf, _parse_buildinfo, _purl
from glance.models import ComponentType, ScanReport, Source

# Minimal synthetic Go binary: ELF magic + Go buildinf magic + text block.
_FAKE_BINARY = (
    b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\xff Go buildinf:\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"go\tgo1.21.0\n"
    b"path\tgithub.com/test/app\n"
    b"mod\tgithub.com/test/app\tv1.2.3\th1:AAA=\n"
    b"dep\tgolang.org/x/net\tv0.1.0\th1:BBB=\n"
    b"dep\tgolang.org/x/crypto\tv0.0.1\th1:CCC=\n"
    b"build\tCGO_ENABLED=0\n"
)

_FAKE_BINARY_DEVEL = (
    b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\xff Go buildinf:\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"go\tgo1.21.0\n"
    b"path\tgithub.com/test/tool\n"
    b"mod\tgithub.com/test/tool\t(devel)\t\n"
    b"dep\tgolang.org/x/text\tv0.3.0\th1:DDD=\n"
)


def _write_binary(tmp_path, name: str, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_is_elf():
    assert _is_elf(b"\x7fELF\x02\x01")
    assert not _is_elf(b"MZ\x00\x00")  # PE
    assert not _is_elf(b"\x7fEL")  # truncated
    assert not _is_elf(b"")


def test_purl_format():
    assert _purl("golang.org/x/net", "v0.1.0") == "pkg:golang/golang.org/x/net@v0.1.0"
    assert _purl("github.com/foo/bar", "v1.2.3") == "pkg:golang/github.com/foo/bar@v1.2.3"


def test_parse_buildinfo_from_bytes():
    data = _FAKE_BINARY
    m = mmap.mmap(-1, len(data))
    m.write(data)
    m.seek(0)
    info = _parse_buildinfo(m)
    m.close()

    assert info is not None
    assert info["go_version"] == "1.21.0"
    assert info["path"] == "github.com/test/app"
    assert info["main_version"] == "v1.2.3"
    assert len(info["deps"]) == 2
    assert info["deps"][0] == {"module": "golang.org/x/net", "version": "v0.1.0"}
    assert info["deps"][1] == {"module": "golang.org/x/crypto", "version": "v0.0.1"}


def test_parse_buildinfo_not_go():
    data = b"\x7fELF\x00" * 64  # ELF but no Go magic
    m = mmap.mmap(-1, len(data))
    m.write(data)
    m.seek(0)
    assert _parse_buildinfo(m) is None
    m.close()


def test_catalog_finds_components(tmp_path):
    _write_binary(tmp_path, "myapp", _FAKE_BINARY)
    cat = GoBinaryCataloger()
    report = ScanReport()
    comps = cat.catalog([str(tmp_path)], report)

    assert report.catalogers[-1].name == "gobinary"
    assert report.catalogers[-1].ran is True

    modules = {c.metadata.get("module", c.purl): c for c in comps}
    assert "github.com/test/app" in modules
    assert "golang.org/x/net" in modules
    assert "golang.org/x/crypto" in modules

    app = modules["github.com/test/app"]
    assert app.version == "v1.2.3"
    assert app.type == ComponentType.APPLICATION
    assert app.source == Source.GO
    assert app.purl == "pkg:golang/github.com/test/app@v1.2.3"

    net = modules["golang.org/x/net"]
    assert net.version == "v0.1.0"
    assert net.type == ComponentType.LIBRARY


def test_catalog_skips_devel_main_module(tmp_path):
    _write_binary(tmp_path, "tool", _FAKE_BINARY_DEVEL)
    comps = GoBinaryCataloger().catalog([str(tmp_path)], ScanReport())
    # main module (devel) is skipped; dep is emitted
    modules = {c.metadata.get("module", ""): c for c in comps}
    assert "github.com/test/tool" not in modules
    assert "golang.org/x/text" in modules


def test_catalog_deduplicates_across_binaries(tmp_path):
    _write_binary(tmp_path, "bin1", _FAKE_BINARY)
    _write_binary(tmp_path, "bin2", _FAKE_BINARY)
    comps = GoBinaryCataloger().catalog([str(tmp_path)], ScanReport())
    purls = [c.purl for c in comps]
    # same module+version must appear only once
    assert len(purls) == len(set(purls))


def test_catalog_skips_non_elf(tmp_path):
    p = tmp_path / "script.sh"
    p.write_bytes(b"#!/bin/sh\necho hello\n")
    comps = GoBinaryCataloger().catalog([str(tmp_path)], ScanReport())
    assert comps == []


def test_catalog_empty_dir(tmp_path):
    report = ScanReport()
    comps = GoBinaryCataloger().catalog([str(tmp_path)], report)
    assert comps == []
    assert report.catalogers[-1].ran is True
