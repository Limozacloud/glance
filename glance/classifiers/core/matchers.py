"""Evidence matchers — a data-driven port of Syft's binary matcher combinators.

A *classifier* is data: a file-glob gate plus a *matcher*. A matcher is a
callable ``(classifier, context) -> list[MatchResult] | None`` where ``None``
means "no match" and a list (possibly empty) means "matched". All version
regexes operate on **bytes** (version strings sit between ``\\x00`` separators),
and are pre-compiled once at import time.
"""

from __future__ import annotations

import glob as _globmod
import os
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass, field

from ... import _glob

Matcher = Callable[["Classifier", "MatcherContext"], "list[MatchResult] | None"]


@dataclass(frozen=True)
class Identity:
    """The package identity a classifier (or branch) assigns to a match."""

    package: str
    purl_template: str
    cpe_templates: tuple[str, ...] = ()


@dataclass
class MatchResult:
    """A single successful match: a version plus the identity to attribute it to."""

    version: str | None
    evidence: str
    #: identity override (set by branching matchers); ``None`` = use the classifier's.
    identity: Identity | None = None


@dataclass
class MatcherContext:
    """Inputs available to a matcher for one file."""

    path: str
    data: bytes
    #: resolve a ``**/lib`` glob to candidate file paths (for shared-lib lookup).
    resolver: Callable[[str], list[str]] = field(default=lambda g: [])
    #: read another file's bytes (shared-lib / supporting evidence).
    reader: Callable[[str], bytes | None] = field(default=lambda p: None)


@dataclass
class Classifier:
    """A binary classifier: the gate + matcher + identity templates."""

    cls: str
    file_globs: list[str]
    matcher: Matcher
    package: str = ""
    purl_template: str = ""
    cpe_templates: list[str] = field(default_factory=list)

    @property
    def identity(self) -> Identity:
        return Identity(self.package, self.purl_template, tuple(self.cpe_templates))


# --------------------------------------------------------------------------- #
# version extraction helpers
# --------------------------------------------------------------------------- #
def _decode(value: bytes | None) -> str | None:
    return None if value is None else value.decode("latin-1", "replace")


def _merge_groups(match: re.Match[bytes], into: dict[str, str]) -> None:
    for key, value in match.groupdict().items():
        if value is not None:
            into[key] = _decode(value)  # type: ignore[assignment]


def _assemble_version(groups: dict[str, str]) -> str | None:
    if groups.get("version"):
        return groups["version"]
    major, minor, patch = groups.get("major"), groups.get("minor"), groups.get("patch")
    if major and minor and patch:
        return f"{major}.{minor}.{patch}"
    return None


# --------------------------------------------------------------------------- #
# leaf matchers
# --------------------------------------------------------------------------- #
def contents(*patterns: bytes) -> Matcher:
    """All ``patterns`` must match the file bytes; named groups are merged.

    Mirrors Syft's ``FileContentsVersionMatcher``: a single matcher with several
    patterns is a logical AND; alternatives are expressed with :func:`any_of`.
    """
    if not patterns:
        raise ValueError("contents() needs at least one pattern")
    compiled = [re.compile(p) for p in patterns]
    evidence = _decode(patterns[0]) or ""

    def _match(_cls: Classifier, ctx: MatcherContext) -> list[MatchResult] | None:
        groups: dict[str, str] = {}
        for pat in compiled:
            m = pat.search(ctx.data)
            if m is None:
                return None
            _merge_groups(m, groups)
        return [MatchResult(_assemble_version(groups), evidence)]

    return _match


def filename_template(filename_pattern: str, content_template: bytes) -> Matcher:
    """Extract groups from the file *path*, render them into a byte-regex template.

    Mirrors Syft's ``FileNameTemplateVersionMatcher`` (e.g. ``python3.11`` ->
    a content pattern that looks for ``\\x003.11...\\x00``).
    """
    fpat = re.compile(filename_pattern)
    evidence = filename_pattern

    def _match(_cls: Classifier, ctx: MatcherContext) -> list[MatchResult] | None:
        fm = fpat.search(ctx.path)
        if fm is None:
            return None
        rendered = content_template
        for key, value in fm.groupdict().items():
            if value is None:
                continue
            escaped = re.escape(value).encode("latin-1", "replace")
            rendered = rendered.replace(b"{{ ." + key.encode() + b" }}", escaped)
        try:
            cpat = re.compile(rendered)
        except re.error:
            return None
        cm = cpat.search(ctx.data)
        if cm is None:
            return None
        groups: dict[str, str] = {}
        _merge_groups(cm, groups)
        return [MatchResult(_assemble_version(groups), evidence)]

    return _match


def path_glob(pattern: str) -> Matcher:
    """Succeed (empty match) when the file path matches the doublestar glob."""

    def _match(_cls: Classifier, ctx: MatcherContext) -> list[MatchResult] | None:
        return [] if _glob.match(pattern, ctx.path) else None

    return _match


# --------------------------------------------------------------------------- #
# combinators
# --------------------------------------------------------------------------- #
def any_of(*matchers: Matcher) -> Matcher:
    """Return the results of the first matcher that matches (logical OR)."""

    def _match(cls: Classifier, ctx: MatcherContext) -> list[MatchResult] | None:
        for matcher in matchers:
            result = matcher(cls, ctx)
            if result is not None:
                return result
        return None

    return _match


def all_of(*matchers: Matcher) -> Matcher:
    """All matchers must match; return the last non-empty results (logical AND)."""

    def _match(cls: Classifier, ctx: MatcherContext) -> list[MatchResult] | None:
        out: list[MatchResult] = []
        for matcher in matchers:
            result = matcher(cls, ctx)
            if result is None:
                return None
            if result:
                out = result
        return out

    return _match


def none_of(matcher: Matcher) -> Matcher:
    """Succeed only if the inner matcher does *not* match (negative gate)."""

    def _match(cls: Classifier, ctx: MatcherContext) -> list[MatchResult] | None:
        return None if matcher(cls, ctx) is not None else []

    return _match


def branching(*classifiers: Classifier) -> Matcher:
    """Try each sub-classifier; the first to match wins and supplies its identity.

    Mirrors Syft's ``BranchingEvidenceMatcher`` (e.g. AWS-LC vs OpenSSL, or the
    several mysqld variants).
    """

    def _match(_cls: Classifier, ctx: MatcherContext) -> list[MatchResult] | None:
        for sub in classifiers:
            result = sub.matcher(sub, ctx)
            if result:
                return [MatchResult(r.version, r.evidence, identity=sub.identity) for r in result]
        return None

    return _match


def shared_library(lib_pattern: str, inner: Matcher) -> Matcher:
    """Look up version evidence in a shared library referenced by this binary.

    Reads the ELF ``DT_NEEDED`` entries, matches them against ``lib_pattern``,
    resolves the library within the candidate set, and runs ``inner`` on it.
    Best-effort: returns ``None`` when the ELF cannot be parsed or the library
    is not in scope (the library is independently gated by its own classifier).
    """
    lpat = re.compile(lib_pattern)

    def _match(cls: Classifier, ctx: MatcherContext) -> list[MatchResult] | None:
        results: list[MatchResult] = []
        for lib in elf_needed(ctx.data):
            if lpat.search(lib) is None:
                continue
            for libpath in ctx.resolver("**/" + lib):
                data = ctx.reader(libpath)
                if not data:
                    continue
                sub = MatcherContext(libpath, data, ctx.resolver, ctx.reader)
                inner_result = inner(cls, sub)
                if inner_result:
                    results.extend(inner_result)
        return results or None

    return _match


def supporting(relative_glob: str, inner: Matcher) -> Matcher:
    """Search for secondary evidence near the file (e.g. a ``VERSION`` sibling)."""

    def _match(cls: Classifier, ctx: MatcherContext) -> list[MatchResult] | None:
        base = os.path.dirname(ctx.path)
        pattern = os.path.normpath(os.path.join(base, relative_glob))
        for found in sorted(_globmod.glob(pattern)):
            data = ctx.reader(found)
            if not data:
                continue
            sub = MatcherContext(found, data, ctx.resolver, ctx.reader)
            result = inner(cls, sub)
            if result is not None:
                return result
        return None

    return _match


# --------------------------------------------------------------------------- #
# ELF helpers
# --------------------------------------------------------------------------- #
ELF_MAGIC = b"\x7fELF"


def is_elf(data: bytes) -> bool:
    return data[:4] == ELF_MAGIC


def elf_needed(data: bytes) -> list[str]:
    """Return the ``DT_NEEDED`` shared-library names of an ELF image.

    Uses section headers (file offsets only, no virtual-address mapping), so it
    works on libraries and executables alike. Returns ``[]`` for stripped
    images without section headers or anything that fails to parse.
    """
    try:
        if not is_elf(data):
            return []
        ei_class = data[4]
        ei_data = data[5]
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            return []
        endian = "<" if ei_data == 1 else ">"
        is64 = ei_class == 2

        if is64:
            (e_shoff,) = struct.unpack_from(endian + "Q", data, 0x28)
            (e_shentsize,) = struct.unpack_from(endian + "H", data, 0x3A)
            (e_shnum,) = struct.unpack_from(endian + "H", data, 0x3C)
        else:
            (e_shoff,) = struct.unpack_from(endian + "I", data, 0x20)
            (e_shentsize,) = struct.unpack_from(endian + "H", data, 0x2E)
            (e_shnum,) = struct.unpack_from(endian + "H", data, 0x30)

        if e_shoff == 0 or e_shnum == 0:
            return []

        dyn_off = dyn_size = dyn_entsize = link = 0
        sections: list[tuple[int, int, int, int, int]] = []
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            if base + e_shentsize > len(data):
                break
            (sh_type,) = struct.unpack_from(endian + "I", data, base + 4)
            if is64:
                (sh_offset,) = struct.unpack_from(endian + "Q", data, base + 0x18)
                (sh_size,) = struct.unpack_from(endian + "Q", data, base + 0x20)
                (sh_link,) = struct.unpack_from(endian + "I", data, base + 0x28)
                (sh_entsize,) = struct.unpack_from(endian + "Q", data, base + 0x38)
            else:
                (sh_offset,) = struct.unpack_from(endian + "I", data, base + 0x10)
                (sh_size,) = struct.unpack_from(endian + "I", data, base + 0x14)
                (sh_link,) = struct.unpack_from(endian + "I", data, base + 0x18)
                (sh_entsize,) = struct.unpack_from(endian + "I", data, base + 0x24)
            sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
            if sh_type == 6:  # SHT_DYNAMIC
                dyn_off, dyn_size, dyn_entsize, link = sh_offset, sh_size, sh_entsize, sh_link

        if dyn_off == 0 or link >= len(sections):
            return []
        _, str_off, str_size, _, _ = sections[link]

        entry_size = dyn_entsize or (16 if is64 else 8)
        tag_fmt = endian + ("q" if is64 else "i")
        val_fmt = endian + ("Q" if is64 else "I")
        val_offset = 8 if is64 else 4

        needed_offsets: list[int] = []
        pos = dyn_off
        end = dyn_off + dyn_size
        while pos + entry_size <= end and pos + entry_size <= len(data):
            (d_tag,) = struct.unpack_from(tag_fmt, data, pos)
            (d_val,) = struct.unpack_from(val_fmt, data, pos + val_offset)
            if d_tag == 0:  # DT_NULL
                break
            if d_tag == 1:  # DT_NEEDED
                needed_offsets.append(d_val)
            pos += entry_size

        out: list[str] = []
        for offset in needed_offsets:
            start = str_off + offset
            if start >= len(data) or start >= str_off + str_size:
                continue
            nul = data.find(b"\x00", start, str_off + str_size)
            if nul == -1:
                continue
            out.append(data[start:nul].decode("latin-1", "replace"))
        return out
    except (struct.error, IndexError, ValueError):
        return []
