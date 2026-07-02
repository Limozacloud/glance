"""Candidate discovery: Linux plocate / Windows MFT.

Linux requires plocate with a pre-built DB — no walk fallback.
Windows uses direct NTFS MFT enumeration.

Public entry point: :func:`discover_all`.
"""

from __future__ import annotations

import logging
import sys

from ..config import Config
from ..models import ScanReport
from . import engines
from .gate import Gate
from .index import FileIndex

log = logging.getLogger(__name__)


def _names_to_globs(names: list[str]) -> list[str]:
    out = []
    for n in names:
        if "*" in n or "/" in n:
            out.append(n)
        elif n.startswith("."):
            out.append(f"**/*{n}")
        else:
            out.append(f"**/{n}")
    return out


def discover_all(
    config: Config, gate: Gate, extra_names: list[str], report: ScanReport
) -> FileIndex:
    """Single filesystem pass returning a FileIndex for binary + ecosystem catalogers."""
    if sys.platform == "win32":
        return _discover_windows(config, gate, extra_names, report)
    return _discover_linux(config, gate, extra_names, report)


def _discover_linux(
    config: Config, gate: Gate, extra_names: list[str], report: ScanReport
) -> FileIndex:
    engine = engines.get_plocate(config)

    extra_gate = Gate(_names_to_globs(extra_names)) if extra_names else None
    anchors, unanchored = engines.anchors_for(gate.globs)

    if unanchored:
        report.warnings.append(
            f"{len(unanchored)} glob(s) have no literal anchor; results may be incomplete"
        )

    combined_anchors = list(anchors) + extra_names

    report.engine_used = "plocate"
    report.engine_reason = f"plocate DB {engine.db_path}"
    report.scanned_paths.append(f"plocate:{engine.db_path}")

    all_paths: set[str] = set()
    considered = 0

    for path in engines.query(engine, combined_anchors):
        considered += 1
        if gate.matches(path) or (extra_gate and extra_gate.matches(path)):
            all_paths.add(path)

    report.files_considered = considered
    return FileIndex(all_paths)


def _discover_windows(
    config: Config, gate: Gate, extra_names: list[str], report: ScanReport
) -> FileIndex:
    from . import mft as _mft

    extra_gate = Gate(_names_to_globs(extra_names)) if extra_names else None
    anchors, _ = engines.anchors_for(gate.globs)

    report.engine_used = "mft"
    report.engine_reason = "Windows MFT fast enumeration"
    drives = _mft.local_drives()
    report.scanned_paths.extend(f"{d}:\\" for d in drives)

    names = [a for a in anchors if not any(c in a for c in ("*", "?", "["))]
    exts = [a for a in anchors if a.startswith(".")]
    combined_names = names + extra_names

    all_paths: set[str] = set()
    considered = 0

    for path in _mft.query(
        drives,
        names=combined_names or None,
        extensions=exts or None,
    ):
        considered += 1
        if gate.matches(path) or (extra_gate and extra_gate.matches(path)):
            all_paths.add(path)

    report.files_considered = considered
    return FileIndex(all_paths)
