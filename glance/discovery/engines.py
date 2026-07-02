"""plocate engine: query binary and DB path.

Linux discovery requires plocate with a pre-built DB. The agent is responsible
for deploying the binary and running updatedb before glance is called.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass

log = logging.getLogger(__name__)

_WILDCARD = re.compile(r"[*?\[\]{}]")


@dataclass
class EngineInfo:
    """A usable plocate engine: its query binary and backing DB."""

    name: str
    binary: str
    db_path: str


def get_plocate(config) -> EngineInfo:
    """Return a ready EngineInfo or raise RuntimeError if plocate is not usable."""
    binary = config.plocate_binary or shutil.which("plocate")
    if not binary or not os.path.isfile(binary):
        raise RuntimeError(
            "plocate binary not found — deploy plocate and set plocate_binary in config"
        )
    db = config.locate_db_path or "/var/lib/plocate/plocate.db"
    if not os.path.isfile(db):
        raise RuntimeError(f"plocate DB not found at {db!r} — run: updatedb --output {db}")
    return EngineInfo(name="plocate", binary=binary, db_path=db)


def literal_anchor(glob: str) -> str | None:
    """Longest literal substring of a glob usable as a locate substring query.

    e.g. ``**/libcrypto.so*`` -> ``libcrypto.so``; ``**/openssl`` -> ``openssl``.
    Returns ``None`` when the glob has no usable literal (locate cannot produce a
    reliable superset — the caller must warn about incomplete results).
    """
    body = glob
    if body.startswith("**/"):
        body = body[3:]
    fragments = _WILDCARD.split(body)
    best = max(fragments, key=len, default="")
    best = best.strip("/")
    return best if len(best) >= 2 else None


def anchors_for(globs: list[str]) -> tuple[list[str], list[str]]:
    """Split globs into (locatable anchors, un-anchorable globs)."""
    anchors: list[str] = []
    unanchored: list[str] = []
    for glob in globs:
        anchor = literal_anchor(glob)
        if anchor is None:
            unanchored.append(glob)
        else:
            anchors.append(anchor)
    return list(dict.fromkeys(anchors)), unanchored


def query(engine: EngineInfo, anchors: list[str]) -> Iterator[str]:
    """Stream candidate paths from plocate for the given substring anchors.

    plocate treats multiple patterns as AND (intersection), so each anchor is
    queried in its own subprocess call. Results are deduplicated across calls.
    Output is NUL-separated to survive odd filenames.
    """
    if not anchors:
        return
    seen: set[str] = set()
    for anchor in anchors:
        cmd = [engine.binary, "-0", "-d", engine.db_path, "--", anchor]
        try:
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False
            )
        except OSError as exc:
            log.warning("plocate query failed: %s", exc)
            continue
        for raw in proc.stdout.split(b"\x00"):
            if raw:
                path = os.fsdecode(raw)
                if path not in seen:
                    seen.add(path)
                    yield path
