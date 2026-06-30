"""Load classifiers from external YAML/JSON — no code changes needed.

A single file can define classifiers for any cataloger using the ``cataloger``
field (``linux_binary``, ``windows_registry``, ``windows_binary``). When
``cataloger`` is omitted it defaults to ``linux_binary``.

Schema (YAML)::

    classifiers:
      # Linux/macOS — byte-regex scan of file contents
      - cataloger: linux_binary
        class: nginx-binary
        file_globs: ["**/nginx"]
        version_patterns:
          - 'nginx version: [^/]+/(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)'
        package: nginx
        purl: "pkg:generic/nginx@{version}"
        cpes: ["cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*"]

      # Windows — match via Registry DisplayName / Publisher
      - cataloger: windows_registry
        id: my-app
        display_name_contains: ["My Application"]
        publisher_contains: ["My Corp"]
        name: my-app
        purl_template: "pkg:generic/my-app@{version}"
        cpe_template: "cpe:2.3:a:mycorp:my_app:{version}:*:*:*:*:*:*:*"

      # Windows — match via PE VERSIONINFO ProductName / CompanyName
      - cataloger: windows_binary
        id: my-app-pe
        product_name_contains: ["My Application"]
        company_contains: ["My Corp"]
        name: my-app
        purl_template: "pkg:generic/my-app@{version}"
        cpe_template: "cpe:2.3:a:mycorp:my_app:{version}:*:*:*:*:*:*:*"

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
    "cataloger",
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

_VALID_CATALOGERS = {"linux_binary", "windows_registry", "windows_binary"}


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
    """Build linux_binary classifiers from a list of declarative mappings."""
    return [_build_classifier(item) for item in items]


def _parse_file(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise ImportError(f"reading the YAML classifier file {path} requires PyYAML") from exc
        data = yaml.safe_load(text)
    elif suffix == ".json":
        data = json.loads(text)
    else:
        raise ValueError(f"unsupported classifier file format {suffix!r} for {path}")
    if isinstance(data, dict):
        data = data.get("classifiers", [])
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list of classifiers or {{classifiers: [...]}}")
    return data


def load_classifier_file(path: str | Path) -> list[Classifier]:
    """Load linux_binary classifiers from a file (backward-compatible).

    Entries with ``cataloger: windows_registry`` or ``cataloger: windows_binary``
    are silently skipped — use :func:`load_classifier_file_split` to extract them.
    """
    classifiers, _, _ = load_classifier_file_split(path)
    return classifiers


def load_classifier_file_split(
    path: str | Path,
) -> tuple[list[Classifier], list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse a classifier file and split entries by cataloger.

    Returns ``(linux_binary_classifiers, windows_registry_entries, windows_binary_entries)``.
    Entries without a ``cataloger`` field default to ``linux_binary``.
    """
    p = Path(path)
    raw = _parse_file(p)

    binary: list[Classifier] = []
    registry: list[dict[str, Any]] = []
    win_binary: list[dict[str, Any]] = []

    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError(f"{p}: each classifier must be a mapping, got {type(entry).__name__}")
        cat = entry.get("cataloger")
        if cat is not None and cat not in _VALID_CATALOGERS:
            raise ValueError(
                f"{p}: unknown cataloger {cat!r} — valid values: "
                + ", ".join(sorted(_VALID_CATALOGERS))
            )
        if cat in (None, "linux_binary"):
            entry_without_cataloger = {k: v for k, v in entry.items() if k != "cataloger"}
            binary.append(_build_classifier(entry_without_cataloger))
        elif cat == "windows_registry":
            registry.append({k: v for k, v in entry.items() if k != "cataloger"})
        elif cat == "windows_binary":
            win_binary.append({k: v for k, v in entry.items() if k != "cataloger"})

    return binary, registry, win_binary
