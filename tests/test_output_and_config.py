from __future__ import annotations

import json

import pytest

from glance.config import Config, Engine, OnStaleDB
from glance.models import (
    Component,
    ComponentType,
    Occurrence,
    ScanReport,
    ScanResult,
    SkipReason,
    Source,
)
from glance.output import report_to_dict, to_cyclonedx, to_native


def _result() -> ScanResult:
    lib = Component(
        name="openssl",
        version="1.1.1w",
        type=ComponentType.LIBRARY,
        source=Source.BINARY,
        purl="pkg:generic/openssl@1.1.1w",
        cpes=["cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"],
        occurrences=[Occurrence(path="/opt/agent/lib/libcrypto.so.1.1", found_by="openssl-binary")],
        managed=False,
        bom_ref="pkg:generic/openssl@1.1.1w#/opt/agent/lib",
        owned_by="app:/opt/agent/lib",
    )
    app = Component(
        name="/opt/agent/lib",
        version=None,
        type=ComponentType.APPLICATION,
        source=Source.BINARY,
        bom_ref="app:/opt/agent/lib",
        managed=False,
        depends_on=[lib.bom_ref],
    )
    report = ScanReport(engine_used="plocate")
    report.skip("/mnt/nfs", SkipReason.CONFIG_FS_TYPE, "nfs")
    return ScanResult(components=[lib, app], report=report, timestamp=1_700_000_000.0)


def test_cyclonedx_structure_and_purl_cpe():
    bom = to_cyclonedx(_result(), tool_version="0.1.0")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    lib = next(c for c in bom["components"] if c["name"] == "openssl")
    assert lib["purl"] == "pkg:generic/openssl@1.1.1w"
    assert lib["cpe"].endswith("1.1.1w:*:*:*:*:*:*:*")
    assert lib["evidence"]["occurrences"][0]["location"].endswith("libcrypto.so.1.1")
    assert {"name": "glance:managed", "value": "false"} in lib["properties"]


def test_cyclonedx_dependency_graph():
    bom = to_cyclonedx(_result())
    deps = bom["dependencies"]
    assert deps[0]["ref"] == "app:/opt/agent/lib"
    assert "pkg:generic/openssl@1.1.1w#/opt/agent/lib" in deps[0]["dependsOn"]


def test_cyclonedx_is_json_serialisable():
    json.dumps(to_cyclonedx(_result()))


def test_native_output():
    native = to_native(_result())
    openssl = next(c for c in native["components"] if c["name"] == "openssl")
    assert openssl["managed"] is False
    assert openssl["paths"] == ["/opt/agent/lib/libcrypto.so.1.1"]


def test_report_serialises_enums_as_values():
    data = report_to_dict(_result().report)
    text = json.dumps(data)  # must not raise
    assert "config:exclude_fs_type" in text
    assert data["skipped"][0]["reason"] == "config:exclude_fs_type"


def test_config_unknown_key_is_hard_error():
    with pytest.raises(ValueError, match="unknown config key"):
        Config.from_dict({"include_paths": ["/usr"], "typo_key": 1})


def test_config_partial_override_keeps_defaults():
    cfg = Config.from_dict({"max_db_age_hours": 6})
    assert cfg.max_db_age_hours == 6
    assert cfg.include_paths == ["/"]  # default preserved
    assert cfg.engine == Engine.AUTO


def test_config_enum_coercion():
    cfg = Config.from_dict({"engine": "walk", "on_stale_db": "warn"})
    assert cfg.engine == Engine.WALK
    assert cfg.on_stale_db == OnStaleDB.WARN


def test_config_from_json_file(tmp_path):
    p = tmp_path / "c.json"
    p.write_text('{"engine": "plocate", "max_file_size": 1024}', encoding="utf-8")
    cfg = Config.from_file(str(p))
    assert cfg.engine == Engine.PLOCATE
    assert cfg.max_file_size == 1024


def test_config_from_yaml_file(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("engine: mlocate\ninclude_paths:\n  - /opt\n", encoding="utf-8")
    cfg = Config.from_file(str(p))
    assert cfg.engine == Engine.MLOCATE
    assert cfg.include_paths == ["/opt"]
