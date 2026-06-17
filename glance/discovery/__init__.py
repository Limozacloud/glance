"""Candidate discovery: pick an engine, gate the results, never skip silently.

Public entry point: :func:`discover`, which returns the de-duplicated set of
gated candidate file paths and fills in the audit trail on the report (which
engine, why, what was skipped).
"""

from __future__ import annotations

import logging

from ..config import Config, Engine, OnStaleDB
from ..models import ScanReport, SkipReason
from . import engines, walk
from .gate import Gate

log = logging.getLogger(__name__)


def _scope_skip(path: str, exclude_paths: list[str], excluded_prefixes: list[str]):
    for prefix in exclude_paths:
        if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return SkipReason.CONFIG_EXCLUDE_PATH, prefix
    for prefix in excluded_prefixes:
        if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return SkipReason.CONFIG_FS_TYPE, prefix
    return None


def _select_engine(config: Config, report: ScanReport):
    """Return a usable EngineInfo or None (meaning: walk). Records the cascade."""
    if config.engine == Engine.WALK:
        report.engine_cascade.append("engine=walk (forced)")
        return None

    available = engines.detect_engines(config.locate_db_path)
    if config.engine in (Engine.PLOCATE, Engine.MLOCATE):
        available = [e for e in available if e.name == config.engine.value]
        if not available:
            report.engine_cascade.append(f"{config.engine.value}: forced but unavailable -> walk")
            report.warnings.append(
                f"engine {config.engine.value} forced but not available; fell back to walk"
            )
            return None

    for engine in available:
        age = engine.db_age_hours()
        if age is None:
            report.engine_cascade.append(f"{engine.name}: DB unreadable -> next")
            report.skip(engine.db_path, SkipReason.DB_MISSING)
            continue
        if age > config.max_db_age_hours:
            detail = f"age={age:.1f}h > max={config.max_db_age_hours}h"
            if config.on_stale_db == OnStaleDB.WARN:
                report.engine_cascade.append(f"{engine.name}: stale ({detail}) -> used (warn)")
                report.warnings.append(f"{engine.name} DB is stale ({detail}); used anyway")
                return engine
            report.engine_cascade.append(f"{engine.name}: stale ({detail}) -> next")
            report.skip(engine.db_path, SkipReason.DB_STALE, detail)
            continue
        report.engine_cascade.append(f"{engine.name}: fresh (age={age:.1f}h) -> used")
        return engine

    report.engine_cascade.append("no usable locate engine -> walk")
    return None


def discover(config: Config, gate: Gate, report: ScanReport) -> set[str]:
    """Discover gated candidate files. Fills the report's engine/skip audit."""
    excluded_prefixes = walk.excluded_mount_prefixes(config.exclude_fs_types)
    candidates: set[str] = set()
    considered = 0

    engine = _select_engine(config, report)

    anchors, unanchored = engines.anchors_for(gate.globs)
    if engine is not None and unanchored:
        # locate cannot safely cover these globs -> fall back to walk for completeness
        report.warnings.append(
            f"{len(unanchored)} glob(s) have no literal anchor; using walk for completeness"
        )
        report.engine_cascade.append("un-anchorable globs present -> walk")
        engine = None

    if engine is not None:
        report.engine_used = engine.name
        report.engine_reason = f"locate DB {engine.db_path}"
        report.scanned_paths.append(f"{engine.name}:{engine.db_path}")
        for path in engines.query(engine, anchors, config.locate_db_path):
            considered += 1
            skip = _scope_skip(path, config.exclude_paths, excluded_prefixes)
            if skip is not None:
                continue  # excluded paths from a huge index aren't worth logging individually
            if gate.matches(path):
                candidates.add(path)
    else:
        report.engine_used = "walk"
        report.engine_reason = report.engine_reason or "no usable locate engine"
        for root in config.include_paths:
            report.scanned_paths.append(root)
            for path in walk.walk_tree(
                root,
                follow_symlinks=config.follow_symlinks,
                excluded_prefixes=excluded_prefixes,
                exclude_paths=config.exclude_paths,
                report=report,
            ):
                considered += 1
                if gate.matches(path):
                    candidates.add(path)

    # mandatory paths: always walked directly, never pruned by config/fs-type
    for root in config.mandatory_paths:
        report.mandatory_paths.append(root)
        for path in walk.walk_tree(
            root,
            follow_symlinks=config.follow_symlinks,
            excluded_prefixes=excluded_prefixes,
            exclude_paths=config.exclude_paths,
            report=report,
            apply_scope=False,
        ):
            considered += 1
            if gate.matches(path):
                candidates.add(path)

    report.files_considered = considered
    return candidates
