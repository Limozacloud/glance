"""FileIndex: in-memory snapshot of all discovered candidate paths.

Built once by discover_all(); queried by binary and ecosystem catalogers
without any further filesystem access.
"""

from __future__ import annotations

import os

from .gate import Gate


class FileIndex:
    """Immutable set of candidate paths indexed by basename for fast lookup."""

    def __init__(self, paths: set[str]) -> None:
        self._paths: frozenset[str] = frozenset(paths)
        self._by_name: dict[str, list[str]] = {}
        for p in self._paths:
            key = os.path.basename(p).lower()
            self._by_name.setdefault(key, []).append(p)

    # ── Queries ───────────────────────────────────────────────────────────────

    def matching_gate(self, gate: Gate) -> set[str]:
        """All paths that pass the given Gate (used by binary cataloger)."""
        return {p for p in self._paths if gate.matches(p)}

    def by_name(self, name: str) -> list[str]:
        """Paths whose basename equals name (case-insensitive)."""
        return list(self._by_name.get(name.lower(), []))

    def by_name_substr(self, substr: str) -> list[str]:
        """Paths whose basename contains substr (case-insensitive).

        Mirrors plocate substring semantics — e.g. "packages.lock.json"
        also finds "MyApp.packages.lock.json".
        """
        s = substr.lower()
        result: list[str] = []
        for key, paths in self._by_name.items():
            if s in key:
                result.extend(paths)
        return result

    @property
    def all_paths(self) -> frozenset[str]:
        return self._paths

    def __len__(self) -> int:
        return len(self._paths)

    def __contains__(self, path: object) -> bool:
        return path in self._paths
