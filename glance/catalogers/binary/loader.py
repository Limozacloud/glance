"""Load binary classifiers from external YAML/JSON — no code changes needed.

A declarative classifier covers the common case (a gate plus one or more byte
regexes); the full combinator power stays in Python. Schema (YAML)::

    classifiers:
      - class: nginx-library
        file_globs: ["**/libnginx.so*"]
        version_patterns:            # OR — first match wins (any_of of contents)
          - 'nginx version: [^/]+/(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)'
        package: nginx
        purl: "pkg:generic/nginx@{version}"
        cpes: ["cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*"]

Notes:
- Patterns are **byte** regexes written as text; ``\\x00`` etc. are interpreted
  by ``re`` (use single-quoted YAML / raw JSON so backslashes survive).
- ``{version}`` in ``purl``/``cpes`` is substituted with the captured version.
- ``all_patterns`` (AND, merges named groups) and ``branches`` (one identity per
  sub-match) are also supported for the less common cases.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .matchers import Classifier, Matcher, all_of, any_of, branching, contents

_ALLOWED_KEYS = {
    "class",
    "file_globs",
    "version_patterns",
    "all_patterns",
    "branches",
    "package",
    "purl",
    "purl_template",
    "cpes",
    "cpe_templates",
}


def _as_bytes(patterns: list[str]) -> list[bytes]:
    return [p.encode("latin-1") for p in patterns]


def _build_matcher(entry: dict[str, Any]) -> Matcher:
    branches = entry.get("branches")
    if branches:
        subs = [_build_classifier(b, gate_required=False) for b in branches]
        return branching(*subs)
    parts: list[Matcher] = []
    if entry.get("version_patterns"):
        parts.append(any_of(*[contents(p) for p in _as_bytes(entry["version_patterns"])]))
    if entry.get("all_patterns"):
        parts.append(all_of(*[contents(p) for p in _as_bytes(entry["all_patterns"])]))
    if not parts:
        raise ValueError(
            f"classifier {entry.get('class')!r} needs one of: "
            "version_patterns, all_patterns, branches"
        )
    return parts[0] if len(parts) == 1 else all_of(*parts)


def _build_classifier(entry: dict[str, Any], gate_required: bool = True) -> Classifier:
    if not isinstance(entry, dict):
        raise ValueError(f"each classifier must be a mapping, got {type(entry).__name__}")
    unknown = set(entry) - _ALLOWED_KEYS
    if unknown:
        raise ValueError(f"unknown classifier key(s): {', '.join(sorted(unknown))}")
    name = entry.get("class")
    if not name:
        raise ValueError("classifier missing required 'class'")
    globs = entry.get("file_globs") or []
    if gate_required and not globs:
        raise ValueError(f"classifier {name!r} missing required 'file_globs'")
    return Classifier(
        cls=name,
        file_globs=list(globs),
        matcher=_build_matcher(entry),
        package=entry.get("package", ""),
        purl_template=entry.get("purl_template") or entry.get("purl", ""),
        cpe_templates=list(entry.get("cpe_templates") or entry.get("cpes") or []),
    )


def classifiers_from_dicts(items: list[dict[str, Any]]) -> list[Classifier]:
    """Build classifiers from a list of declarative mappings."""
    return [_build_classifier(item) for item in items]


def load_classifier_file(path: str | Path) -> list[Classifier]:
    """Load classifiers from a ``.yaml``/``.yml`` or ``.json`` file.

    The document may be a bare list of classifiers or ``{"classifiers": [...]}``.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise ImportError(f"reading the YAML classifier file {p} requires PyYAML") from exc
        data = yaml.safe_load(text)
    elif suffix == ".json":
        data = json.loads(text)
    else:
        raise ValueError(f"unsupported classifier file format {suffix!r} for {p}")
    if isinstance(data, dict):
        data = data.get("classifiers", [])
    if not isinstance(data, list):
        raise ValueError(f"{p}: expected a list of classifiers or {{classifiers: [...]}}")
    return classifiers_from_dicts(data)
