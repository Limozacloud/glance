"""Scan configuration.

Defaults live here in code, so glance runs out-of-the-box with zero config and
zero YAML dependency (important for embedding as a library). A YAML/JSON file is
optional and only partial overrides are needed — present keys win, absent keys
keep their default.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any


@dataclass
class Config:
    """All knobs for a scan. See ``glance/default_config.yaml`` for docs."""

    # --- scope -----------------------------------------------------------------
    #: Glob gate. ``None`` means "derive from the active classifiers" (default).
    file_globs: list[str] | None = None

    # --- discovery engine (Linux: plocate required) ----------------------------
    #: Path to the plocate binary. ``None`` searches $PATH.
    plocate_binary: str | None = None
    #: Path to the plocate DB. ``None`` uses /var/lib/plocate/plocate.db.
    locate_db_path: str | None = None

    # --- catalogers ------------------------------------------------------------
    #: Which catalogers to run. ``None`` = all that are applicable on this host.
    catalogers: list[str] | None = None
    #: Ecosystem scan depth: "installed" (default) reads the actual install store
    #: (.dist-info, node_modules, JARs, gemspecs) for server/container scans;
    #: "project" reads manifest/lock-files (requirements.txt, go.sum, pom.xml …)
    #: for repo/CI scans.
    ecosystem_mode: str = "installed"
    #: Correlate binary finds against package-DB file ownership (managed/unmanaged).
    correlate_ownership: bool = True
    #: Extra binary-classifier definition files (YAML/JSON) loaded in addition to
    #: the built-ins — add classifiers without touching code.
    classifier_files: list[str] = field(default_factory=list)
    # --- Windows PE binary scan ------------------------------------------------
    #: File extensions considered for Windows PE binary scanning.
    win_pe_extensions: list[str] = field(default_factory=lambda: [".dll", ".exe", ".sys"])

    # --- content scan ----------------------------------------------------------
    #: Skip content scan of files larger than this (bytes). Checked lazily.
    max_file_size: int = 200 * 1024 * 1024
    #: Read only the first 4 bytes for the ELF magic before a full content scan.
    #: Off by default: some classifiers target scripts (composer, wp, elixir.app),
    #: so a global ELF gate would cause silent false negatives. Enabling it speeds
    #: up scans at the cost of skipping non-ELF matches (recorded in the report).
    elf_precheck: bool = False
    #: Compute sha256 of matched files (extra I/O; off by default).
    compute_sha256: bool = False

    # --- logging ---------------------------------------------------------------
    log_level: str = "INFO"

    # ---------------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Build a Config from a mapping, applying overrides on top of defaults.

        Unknown keys are a hard error — a typo in the scope config must not
        silently widen or narrow what gets scanned.
        """
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(
                f"unknown config key(s): {', '.join(sorted(unknown))}. "
                f"valid keys: {', '.join(sorted(known))}"
            )
        return cls(**data)

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        """Load config from a ``.yaml``/``.yml`` or ``.json`` file."""
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        suffix = p.suffix.lower()
        if suffix in (".yaml", ".yml"):
            data = _load_yaml(text, str(p))
        elif suffix == ".json":
            data = json.loads(text)
        else:
            raise ValueError(f"unsupported config format {suffix!r} for {p}; use .yaml or .json")
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ValueError(f"config root must be a mapping, got {type(data).__name__}")
        return cls.from_dict(data)


def _load_yaml(text: str, source: str) -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - exercised only without PyYAML
        raise ImportError(
            f"reading the YAML config {source} requires PyYAML "
            "(pip install glance, or use a .json config)"
        ) from exc
    return yaml.safe_load(text)
