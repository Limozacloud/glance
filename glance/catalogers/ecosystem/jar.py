"""Maven/JAR installed packages cataloger — reads pom.properties from JAR files.

Every Maven-built JAR embeds its coordinates at:
  META-INF/maven/<groupId>/<artifactId>/pom.properties

Example content:
  groupId=org.springframework
  artifactId=spring-core
  version=5.3.20

This gives exact deployed versions without relying on pom.xml (which may use
property placeholders) or the Maven local repo (~/.m2/).
"""

from __future__ import annotations

import os
import zipfile

from ...models import Source
from .base import _SKIP_DIRS, EcosystemCataloger


class JarCataloger(EcosystemCataloger):
    name = "jar"
    source = Source.MAVEN

    def manifest_filenames(self) -> list[str]:
        return [".jar"]  # substring match finds *.jar via by_name_substr

    def _is_manifest(self, filename: str) -> bool:
        return filename.endswith(".jar")

    def _index_candidates(self, index) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for path in index.by_name_substr(".jar"):
            if path in seen:
                continue
            if not self._is_manifest(os.path.basename(path)):
                continue
            seen.add(path)
            found.append(path)
        return found

    def _walk_candidates(self) -> list[str]:
        found: list[str] = []
        for root in self.paths:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
                for fname in filenames:
                    if fname.endswith(".jar"):
                        found.append(os.path.join(dirpath, fname))
        return found

    def _purl(self, name: str, version: str | None) -> str:
        v = version or "*"
        # name is "groupId/artifactId" — matches pkg:maven/<group>/<artifact>@<ver>
        return f"pkg:maven/{name}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                return self._extract_pom_properties(zf)
        except (zipfile.BadZipFile, OSError):
            return []

    def _extract_pom_properties(self, zf: zipfile.ZipFile) -> list[tuple[str, str | None]]:
        results: list[tuple[str, str | None]] = []
        for entry in zf.namelist():
            if not (entry.startswith("META-INF/maven/") and entry.endswith("/pom.properties")):
                continue
            try:
                raw = zf.read(entry).decode("utf-8", errors="replace")
            except (KeyError, OSError):
                continue
            props: dict[str, str] = {}
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, _, v = line.partition("=")
                    props[k.strip()] = v.strip()
            group_id = props.get("groupId")
            artifact_id = props.get("artifactId")
            version = props.get("version")
            if group_id and artifact_id:
                results.append((f"{group_id}/{artifact_id}", version or None))
        return results
