"""locate-engine detection and querying (plocate / mlocate).

Engines are detected via their concrete binaries and DB files — never by
assuming ``locate`` is present (it is often an alias and does not tell you which
engine, and the DB formats are mutually incompatible). locate is used only as a
fast index that returns a *superset* of candidates; the gate is the authority.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass

log = logging.getLogger(__name__)

_WILDCARD = re.compile(r"[*?\[\]{}]")


@dataclass
class EngineInfo:
    """A usable locate engine: its query binary and backing DB."""

    name: str  # "plocate" | "mlocate"
    binary: str
    db_path: str

    def db_age_hours(self) -> float | None:
        try:
            mtime = os.stat(self.db_path).st_mtime
        except OSError:
            return None
        return max(0.0, (time.time() - mtime) / 3600.0)


def _probe(
    name: str, binaries: list[str], default_db: str, db_override: str | None
) -> EngineInfo | None:
    binary = next((b for b in (shutil.which(x) for x in binaries) if b), None)
    if binary is None:
        return None
    db_path = db_override or default_db
    if not os.path.isfile(db_path):
        return None
    return EngineInfo(name=name, binary=binary, db_path=db_path)


def detect_engines(db_override: str | None = None) -> list[EngineInfo]:
    """Return available engines in cascade preference order (plocate, mlocate)."""
    engines: list[EngineInfo] = []
    plocate = _probe("plocate", ["plocate"], "/var/lib/plocate/plocate.db", db_override)
    if plocate:
        engines.append(plocate)
    mlocate = _probe("mlocate", ["locate", "mlocate"], "/var/lib/mlocate/mlocate.db", db_override)
    if mlocate:
        engines.append(mlocate)
    return engines


def literal_anchor(glob: str) -> str | None:
    """Longest literal substring of a glob, usable as a locate substring query.

    e.g. ``**/libcrypto.so*`` -> ``libcrypto.so``; ``**/openssl`` -> ``openssl``.
    Returns ``None`` when the glob has no usable literal (locate cannot then be
    trusted to produce a superset for it — the caller must fall back to a walk).
    """
    # strip a leading recursive prefix
    body = glob
    if body.startswith("**/"):
        body = body[3:]
    fragments = _WILDCARD.split(body)
    # also split on '{' alternation remains, but braces are wildcards above
    best = max(fragments, key=len, default="")
    best = best.strip("/")
    return best if len(best) >= 2 else None


def anchors_for(globs: list[str]) -> tuple[list[str], list[str]]:
    """Split globs into (locatable anchors, un-anchorable globs).

    The second list signals globs for which locate alone would be unsafe.
    """
    anchors: list[str] = []
    unanchored: list[str] = []
    for glob in globs:
        anchor = literal_anchor(glob)
        if anchor is None:
            unanchored.append(glob)
        else:
            anchors.append(anchor)
    return list(dict.fromkeys(anchors)), unanchored


def query(engine: EngineInfo, anchors: list[str], db_override: str | None = None) -> Iterator[str]:
    """Stream candidate paths from the engine for the given substring anchors.

    locate ORs multiple patterns, so one invocation returns the union. Output is
    NUL-separated to survive odd filenames.
    """
    if not anchors:
        return
    cmd = [engine.binary, "-0"]
    if db_override:
        cmd += ["-d", db_override]
    cmd += ["--", *anchors]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    except OSError as exc:
        log.warning("locate query failed (%s): %s", engine.name, exc)
        return
    for raw in proc.stdout.split(b"\x00"):
        if raw:
            yield os.fsdecode(raw)
