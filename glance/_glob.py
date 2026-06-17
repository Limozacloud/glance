"""Doublestar-style glob matching, compatible with Syft's ``**/glob*`` syntax.

``fnmatch`` is not enough: Syft globs match against the full path and use ``**``
to cross directory separators (``*`` does not). We also support ``{a,b}``
brace alternation (e.g. ``**/{go,go.exe}``). Globs are matched against the
absolute path with a full match.
"""

from __future__ import annotations

import re
from functools import lru_cache


def _expand_braces(glob: str) -> list[str]:
    """Expand a single level of ``{a,b,c}`` alternation into separate globs."""
    start = glob.find("{")
    if start == -1:
        return [glob]
    depth = 0
    end = -1
    for i in range(start, len(glob)):
        if glob[i] == "{":
            depth += 1
        elif glob[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end == -1:
        return [glob]
    prefix, body, suffix = glob[:start], glob[start + 1 : end], glob[end + 1 :]
    out: list[str] = []
    for option in body.split(","):
        out.extend(_expand_braces(prefix + option + suffix))
    return out


def _translate_one(glob: str) -> str:
    """Translate one brace-free glob into a regex string (no anchoring)."""
    out: list[str] = []
    i = 0
    n = len(glob)
    while i < n:
        c = glob[i]
        if c == "*":
            if i + 1 < n and glob[i + 1] == "*":
                out.append(".*")  # ** crosses '/'
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = i + 1
            if j < n and glob[j] in ("!", "^"):
                j += 1
            if j < n and glob[j] == "]":
                j += 1
            while j < n and glob[j] != "]":
                j += 1
            if j >= n:
                out.append(r"\[")
            else:
                inner = glob[i + 1 : j]
                if inner.startswith(("!", "^")):
                    inner = "^" + inner[1:]
                out.append("[" + inner + "]")
                i = j + 1
                continue
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


@lru_cache(maxsize=2048)
def _compile(glob: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(_translate_one(g) + r"\Z") for g in _expand_braces(glob))


def match(glob: str, path: str) -> bool:
    """Return True if ``path`` matches the doublestar ``glob``.

    Backslashes are normalised to ``/`` so the matcher behaves consistently when
    developing on Windows; on the Linux targets paths already use ``/``.
    """
    norm = path.replace("\\", "/")
    return any(pat.match(norm) is not None for pat in _compile(glob))


def match_any(globs: list[str], path: str) -> bool:
    """Return True if ``path`` matches any of ``globs``."""
    return any(match(g, path) for g in globs)
