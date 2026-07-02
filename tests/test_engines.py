from __future__ import annotations

import os

from glance.discovery.engines import EngineInfo, anchors_for, literal_anchor


def test_literal_anchor():
    assert literal_anchor("**/libcrypto.so*") == "libcrypto.so"
    assert literal_anchor("**/openssl") == "openssl"
    assert literal_anchor("**/libpython*.so*") == "libpython"
    assert literal_anchor("**/libstd-????????????????.so") == "libstd-"
    assert literal_anchor("**/a*") is None


def test_anchors_for_splits_anchorable_and_not():
    anchors, unanchored = anchors_for(["**/openssl", "**/libssl.so*", "**/?"])
    assert "openssl" in anchors and "libssl.so" in anchors
    assert "**/?" in unanchored


def test_get_plocate_missing_binary(tmp_path, monkeypatch):
    import shutil
    from glance.config import Config
    from glance.discovery.engines import get_plocate

    monkeypatch.setattr(shutil, "which", lambda _: None)
    cfg = Config(plocate_binary=None, locate_db_path=str(tmp_path / "db"))
    try:
        get_plocate(cfg)
        assert False, "should have raised"
    except RuntimeError as exc:
        assert "plocate binary not found" in str(exc)


def test_get_plocate_missing_db(tmp_path, monkeypatch):
    import shutil
    from glance.config import Config
    from glance.discovery.engines import get_plocate

    fake_bin = tmp_path / "plocate"
    fake_bin.write_bytes(b"x")
    cfg = Config(plocate_binary=str(fake_bin), locate_db_path=str(tmp_path / "missing.db"))
    try:
        get_plocate(cfg)
        assert False, "should have raised"
    except RuntimeError as exc:
        assert "DB not found" in str(exc)


def test_get_plocate_success(tmp_path):
    from glance.config import Config
    from glance.discovery.engines import get_plocate

    fake_bin = tmp_path / "plocate"
    fake_bin.write_bytes(b"x")
    fake_db = tmp_path / "plocate.db"
    fake_db.write_bytes(b"x")
    cfg = Config(plocate_binary=str(fake_bin), locate_db_path=str(fake_db))
    eng = get_plocate(cfg)
    assert eng.binary == str(fake_bin)
    assert eng.db_path == str(fake_db)
