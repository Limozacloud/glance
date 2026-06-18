from __future__ import annotations

import os

import pytest

from glance import Config, scan
from glance.catalogers.binary import BinaryCataloger
from glance.catalogers.binary.loader import classifiers_from_dicts, load_classifier_file
from glance.config import Engine
from glance.models import ScanReport

FOO_BLOB = b"\x7fELF\x02\x01\x01" + b"\x00" * 16 + b"\x00FooLib 1.2.3\x00" + b"\x00" * 8

FOO_DEF = {
    "class": "foolib-library",
    "file_globs": ["**/libfoo.so*"],
    "version_patterns": [r"\x00FooLib (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00"],
    "package": "foo",
    "purl": "pkg:generic/foo@{version}",
    "cpes": ["cpe:2.3:a:foo:foo:{version}:*:*:*:*:*:*:*"],
}


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def test_classifiers_from_dicts_matches(tmp_path):
    classifiers = classifiers_from_dicts([FOO_DEF])
    p = _write(str(tmp_path / "usr/lib/libfoo.so.1"), FOO_BLOB)
    comps = BinaryCataloger(classifiers).catalog({p}, Config(), ScanReport())
    assert len(comps) == 1
    assert comps[0].name == "foo"
    assert comps[0].version == "1.2.3"
    assert comps[0].purl == "pkg:generic/foo@1.2.3"
    assert comps[0].cpes == ["cpe:2.3:a:foo:foo:1.2.3:*:*:*:*:*:*:*"]


def test_unknown_key_is_error():
    with pytest.raises(ValueError, match="unknown classifier key"):
        classifiers_from_dicts([{**FOO_DEF, "typo": 1}])


def test_missing_class_is_error():
    with pytest.raises(ValueError, match="missing required 'class'"):
        classifiers_from_dicts([{"file_globs": ["**/x"], "version_patterns": ["x"]}])


def test_load_yaml_file(tmp_path):
    f = tmp_path / "extra.yaml"
    f.write_text(
        "classifiers:\n"
        "  - class: foolib-library\n"
        '    file_globs: ["**/libfoo.so*"]\n'
        "    version_patterns:\n"
        "      - '\\x00FooLib (?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)\\x00'\n"
        "    package: foo\n"
        '    purl: "pkg:generic/foo@{version}"\n',
        encoding="utf-8",
    )
    classifiers = load_classifier_file(str(f))
    assert classifiers[0].cls == "foolib-library"


def test_load_json_bare_list(tmp_path):
    import json

    f = tmp_path / "extra.json"
    f.write_text(json.dumps([FOO_DEF]), encoding="utf-8")
    assert load_classifier_file(str(f))[0].package == "foo"


def test_scan_uses_external_classifier_file(tmp_path):
    f = tmp_path / "extra.json"
    import json

    f.write_text(json.dumps([FOO_DEF]), encoding="utf-8")
    _write(str(tmp_path / "opt/agent/libfoo.so.1"), FOO_BLOB)
    cfg = Config(
        engine=Engine.WALK,
        include_paths=[str(tmp_path)],
        mandatory_paths=[],
        catalogers=["binary"],
        correlate_ownership=False,
        classifier_files=[str(f)],
    )
    result = scan(cfg)
    foos = [c for c in result.components if c.name == "foo"]
    assert foos and foos[0].version == "1.2.3"
