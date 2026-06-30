from __future__ import annotations

import os

from glance.config import Config, Engine, OnStaleDB
from glance.discovery import _select_engine, engines
from glance.discovery import mft as _mft_mod
from glance.discovery.engines import EngineInfo, anchors_for, literal_anchor
from glance.models import ScanReport, SkipReason


def test_literal_anchor():
    assert literal_anchor("**/libcrypto.so*") == "libcrypto.so"
    assert literal_anchor("**/openssl") == "openssl"
    assert literal_anchor("**/libpython*.so*") == "libpython"
    assert literal_anchor("**/libstd-????????????????.so") == "libstd-"
    # too short -> not usable
    assert literal_anchor("**/a*") is None


def test_anchors_for_splits_anchorable_and_not():
    anchors, unanchored = anchors_for(["**/openssl", "**/libssl.so*", "**/?"])
    assert "openssl" in anchors and "libssl.so" in anchors
    assert "**/?" in unanchored


def _fake_engine(tmp_path, age_hours: float) -> EngineInfo:
    db = tmp_path / "db"
    db.write_bytes(b"x")
    # set mtime in the past
    import time

    os.utime(db, (time.time() - age_hours * 3600, time.time() - age_hours * 3600))
    return EngineInfo(name="plocate", binary="/usr/bin/plocate", db_path=str(db))


def test_select_engine_fresh(monkeypatch, tmp_path):
    eng = _fake_engine(tmp_path, age_hours=1.0)
    monkeypatch.setattr(engines, "detect_engines", lambda override=None: [eng])
    report = ScanReport()
    chosen = _select_engine(Config(max_db_age_hours=24), report)
    assert chosen is eng
    assert "used" in report.engine_cascade[-1]


def test_select_engine_stale_falls_back(monkeypatch, tmp_path):
    eng = _fake_engine(tmp_path, age_hours=100.0)
    monkeypatch.setattr(engines, "detect_engines", lambda override=None: [eng])
    monkeypatch.setattr(_mft_mod, "available", lambda: False)
    report = ScanReport()
    chosen = _select_engine(Config(max_db_age_hours=24, on_stale_db=OnStaleDB.FALLBACK), report)
    assert chosen is None
    assert any(s.reason == SkipReason.DB_STALE for s in report.skipped)


def test_select_engine_stale_warn_uses_anyway(monkeypatch, tmp_path):
    eng = _fake_engine(tmp_path, age_hours=100.0)
    monkeypatch.setattr(engines, "detect_engines", lambda override=None: [eng])
    report = ScanReport()
    chosen = _select_engine(Config(max_db_age_hours=24, on_stale_db=OnStaleDB.WARN), report)
    assert chosen is eng
    assert report.warnings


def test_forced_walk(monkeypatch):
    report = ScanReport()
    chosen = _select_engine(Config(engine=Engine.WALK), report)
    assert chosen is None


def test_forced_engine_unavailable_falls_back(monkeypatch):
    monkeypatch.setattr(engines, "detect_engines", lambda override=None: [])
    report = ScanReport()
    chosen = _select_engine(Config(engine=Engine.PLOCATE), report)
    assert chosen is None
    assert report.warnings
