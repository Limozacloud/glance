from __future__ import annotations

import os

from glance.config import Config, Engine
from glance.discovery import discover, walk
from glance.discovery.gate import Gate
from glance.models import ScanReport, SkipReason


def _touch(path: str, data: bytes = b"x") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def test_walk_reports_missing_root():
    report = ScanReport()
    list(
        walk.walk_tree(
            "/no/such/path",
            follow_symlinks=False,
            excluded_prefixes=[],
            exclude_paths=[],
            report=report,
        )
    )
    assert any(s.reason == SkipReason.NOT_FOUND for s in report.skipped)


def test_walk_honours_exclude_paths(tmp_path):
    keep = _touch(str(tmp_path / "keep/libcrypto.so.1.1"))
    _touch(str(tmp_path / "skip/libcrypto.so.1.1"))
    report = ScanReport()
    found = list(
        walk.walk_tree(
            str(tmp_path),
            follow_symlinks=False,
            excluded_prefixes=[],
            exclude_paths=[str(tmp_path / "skip")],
            report=report,
        )
    )
    assert keep in found
    assert any(s.reason == SkipReason.CONFIG_EXCLUDE_PATH for s in report.skipped)


def test_discover_walk_engine_gates_candidates(tmp_path):
    target = _touch(str(tmp_path / "opt/agent/libcrypto.so.1.1"))
    _touch(str(tmp_path / "opt/agent/notes.txt"))
    cfg = Config(
        engine=Engine.WALK,
        include_paths=[str(tmp_path)],
        mandatory_paths=[],
        file_globs=["**/libcrypto.so*"],
    )
    gate = Gate(cfg.file_globs)
    report = ScanReport()
    candidates = discover(cfg, gate, report)
    assert target in candidates
    assert all("libcrypto.so" in c for c in candidates)
    assert report.engine_used == "walk"
    assert report.files_considered >= 2


def test_mandatory_paths_walked_even_with_engine(monkeypatch, tmp_path):
    # force the locate branch off (no engines) but ensure mandatory path is walked
    target = _touch(str(tmp_path / "mandatory/libssl.so.3"))
    cfg = Config(
        engine=Engine.WALK,
        include_paths=["/nonexistent-root"],
        mandatory_paths=[str(tmp_path / "mandatory")],
        file_globs=["**/libssl.so*"],
    )
    report = ScanReport()
    candidates = discover(cfg, Gate(cfg.file_globs), report)
    assert target in candidates
    assert str(tmp_path / "mandatory") in report.mandatory_paths
