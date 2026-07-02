from __future__ import annotations

import os
import sys

import pytest

from glance.config import Config
from glance.discovery import discover_all, engines
from glance.discovery.engines import EngineInfo
from glance.discovery.gate import Gate
from glance.models import ScanReport


def _touch(path: str, data: bytes = b"x") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


@pytest.mark.skipif(sys.platform == "win32", reason="Linux plocate path only")
def test_discover_linux_gates_candidates(monkeypatch, tmp_path):
    target = _touch(str(tmp_path / "opt/agent/libcrypto.so.1.1"))
    _touch(str(tmp_path / "opt/agent/notes.txt"))

    fake_bin = tmp_path / "plocate"
    fake_db = tmp_path / "plocate.db"
    fake_bin.write_bytes(b"x")
    fake_db.write_bytes(b"x")

    cfg = Config(
        plocate_binary=str(fake_bin),
        locate_db_path=str(fake_db),
        file_globs=["**/libcrypto.so*"],
    )

    engine = EngineInfo("plocate", str(fake_bin), str(fake_db))
    monkeypatch.setattr(engines, "get_plocate", lambda _cfg: engine)
    monkeypatch.setattr(
        engines,
        "query",
        lambda _eng, _anchors: iter([target, str(tmp_path / "opt/agent/notes.txt")]),
    )

    gate = Gate(cfg.file_globs)
    report = ScanReport()
    idx = discover_all(cfg, gate, [], report)

    assert target in idx.all_paths
    assert str(tmp_path / "opt/agent/notes.txt") not in idx.all_paths
    assert report.engine_used == "plocate"


@pytest.mark.skipif(sys.platform == "win32", reason="Linux path only")
def test_discover_linux_plocate_missing_raises(monkeypatch, tmp_path):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: None)
    cfg = Config(plocate_binary=None, locate_db_path=str(tmp_path / "missing.db"))

    with pytest.raises(RuntimeError, match="plocate"):
        discover_all(cfg, Gate(["**/libssl.so*"]), [], ScanReport())
