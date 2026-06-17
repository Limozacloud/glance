"""The glob gate — the single authority deciding which files are interesting.

Every candidate, whether it came from a locate engine (as a cheap superset) or
from the filesystem walk, passes through *this same* gate. That invariant is
what guarantees the engine choice only affects speed, never which files match
(no silent false negatives from engine selection).
"""

from __future__ import annotations

from .. import _glob


class Gate:
    """Matches a path against a set of doublestar globs (basename/path aware)."""

    def __init__(self, globs: list[str]) -> None:
        # de-duplicate while preserving order
        self.globs = list(dict.fromkeys(globs))

    def matches(self, path: str) -> bool:
        return _glob.match_any(self.globs, path)


def derive_globs(classifiers) -> list[str]:
    """Collect the union of all classifier file-globs (the default gate)."""
    globs: list[str] = []
    for classifier in classifiers:
        globs.extend(classifier.file_globs)
    return list(dict.fromkeys(globs))
