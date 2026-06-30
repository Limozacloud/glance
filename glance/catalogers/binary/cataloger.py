"""Binary content cataloger: read gated candidates, classify, merge.

Reads only the small gated candidate set (never whole trees), memory-maps each
file instead of copying it, and consolidates identical finds (same name +
version, possibly at several paths or via several classifiers) into a single
component with multiple occurrences — Syft's primary-vs-supporting-evidence
behaviour, with classifier-definition order deciding precedence.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import mmap
import os
import re

from ... import _glob
from ...classifiers.core.matchers import Classifier, MatcherContext, MatchResult, is_elf
from ...classifiers.linux_binary import default_classifiers
from ...config import Config
from ...models import Component, ComponentType, Occurrence, ScanReport, SkipReason, Source

log = logging.getLogger(__name__)


_LEFTOVER_TEMPLATE = re.compile(r"\{\{[^}]*\}\}")


def _apply_version(template: str, version: str | None) -> str | None:
    if not template:
        return None
    if version:
        out = template.replace("{version}", version)
    else:
        # no version: drop the version token (and a trailing @ separator)
        out = template.replace("@{version}", "").replace("{version}", "")
    return _LEFTOVER_TEMPLATE.sub("", out)


def _build_cpes(templates: list[str], version: str | None) -> list[str]:
    return [_LEFTOVER_TEMPLATE.sub("*", t.replace("{version}", version or "*")) for t in templates]


class BinaryCataloger:
    name = "binary"

    def __init__(
        self,
        classifiers: list[Classifier] | None = None,
        container_map: dict | None = None,
    ) -> None:
        self.classifiers = classifiers if classifiers is not None else default_classifiers()
        self._container_map: dict = container_map or {}

    def catalog(self, candidates: set[str], config: Config, report: ScanReport) -> list[Component]:
        ordered = sorted(candidates)

        def resolver(glob: str) -> list[str]:
            return [p for p in ordered if _glob.match(glob, p)]

        merged: dict[tuple, Component] = {}
        for path in ordered:
            self._scan_one(path, config, report, resolver, merged)
        return list(merged.values())

    # -- internals ----------------------------------------------------------- #
    def _scan_one(self, path, config, report, resolver, merged) -> None:
        opened: list[mmap.mmap] = []

        def reader(p: str) -> bytes | None:
            data = self._map(p, config, report, opened, count=False)
            return data

        try:
            data = self._map(path, config, report, opened, count=True)
            if data is None:
                return
            if config.elf_precheck and not is_elf(data):
                report.skip(path, SkipReason.NOT_ELF)
                return
            ctx = MatcherContext(path=path, data=data, resolver=resolver, reader=reader)
            sha = None
            for index, classifier in enumerate(self.classifiers):
                if not _glob.match_any(classifier.file_globs, path):
                    continue
                results = classifier.matcher(classifier, ctx)
                if results is None:
                    continue
                if not results:
                    results = [MatchResult(None, classifier.cls)]
                if sha is None and config.compute_sha256:
                    sha = hashlib.sha256(data).hexdigest()
                for result in results:
                    identity = result.identity or classifier.identity
                    self._record(merged, identity, result, classifier, path, sha, index)
        finally:
            for mm in opened:
                with contextlib.suppress(Exception):
                    mm.close()

    def _record(self, merged, identity, result, classifier, path, sha, order) -> None:
        from ...discovery.containers import container_for_path

        version = result.version
        meta: dict = {"classifier_order": order}
        cinfo = container_for_path(path, self._container_map)
        if cinfo:
            meta["container"] = cinfo["name"]
        component = Component(
            name=identity.package or classifier.package or classifier.cls,
            version=version,
            type=ComponentType.LIBRARY,
            source=Source.BINARY,
            purl=_apply_version(identity.purl_template, version),
            cpes=_build_cpes(list(identity.cpe_templates), version),
            occurrences=[
                Occurrence(path=path, found_by=classifier.cls, evidence=result.evidence, sha256=sha)
            ],
            managed=None,
            metadata=meta,
        )
        component.bom_ref = component.purl or f"{component.name}@{version}:{path}"
        key = component.key
        existing = merged.get(key)
        if existing is None:
            merged[key] = component
            return
        # consolidate: add a new occurrence only if this path is not already present
        known = {occ.path for occ in existing.occurrences}
        if path not in known:
            existing.occurrences.extend(component.occurrences)

    def _map(self, path, config, report, opened, count) -> bytes | None:
        try:
            st = os.stat(path)
        except OSError:
            report.skip(path, SkipReason.NOT_FOUND)
            return None
        if st.st_size > config.max_file_size:
            report.skip(path, SkipReason.MAX_FILE_SIZE, f"{st.st_size} bytes")
            return None
        if st.st_size == 0:
            return b""
        try:
            fh = open(path, "rb")  # noqa: SIM115 - mmap needs the live fd
        except OSError as exc:
            report.skip(path, SkipReason.PERMISSION_DENIED, str(exc))
            return None
        try:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError) as exc:
            report.skip(path, SkipReason.READ_ERROR, str(exc))
            return None
        finally:
            fh.close()
        opened.append(mm)
        if count:
            report.files_read += 1
        # mmap is a bytes-like ReadableBuffer; re.search accepts it directly.
        return mm  # type: ignore[return-value]
