"""Ecosystem (language package manager) catalogers."""

from __future__ import annotations

from .distinfo import DistInfoCataloger
from .gem import GemCataloger
from .gem_installed import GemInstalledCataloger
from .go import GoCataloger
from .jar import JarCataloger
from .maven import MavenCataloger
from .node_installed import NodeInstalledCataloger
from .npm import NpmCataloger
from .nuget import NugetCataloger
from .pip import PipCataloger

#: Manifest / lock-file based catalogers — suitable for repo / CI scans.
ECOSYSTEM_PROJECT_CATALOGERS: dict[str, type] = {
    "pip": PipCataloger,
    "go": GoCataloger,
    "npm": NpmCataloger,
    "nuget": NugetCataloger,
    "maven": MavenCataloger,
    "gem": GemCataloger,
}

#: Install-store based catalogers — suitable for server / container scans.
#: Each reads what is actually deployed, not what a lock-file describes.
ECOSYSTEM_INSTALLED_CATALOGERS: dict[str, type] = {
    "distinfo": DistInfoCataloger,  # Python: .dist-info/METADATA  (installed via pip/uv/…)
    "node_installed": NodeInstalledCataloger,  # Node: node_modules/*/package.json
    "jar": JarCataloger,  # Java: META-INF/maven/**/pom.properties in JARs
    "gem_installed": GemInstalledCataloger,  # Ruby: specifications/*.gemspec filenames
    "nuget": NugetCataloger,  # .NET: .deps.json is already install-level
    # Go: gobinary (handled outside ecosystem pipeline)
}

__all__ = [
    "DistInfoCataloger",
    "GemCataloger",
    "GemInstalledCataloger",
    "GoCataloger",
    "JarCataloger",
    "MavenCataloger",
    "NodeInstalledCataloger",
    "NpmCataloger",
    "NugetCataloger",
    "PipCataloger",
    "ECOSYSTEM_PROJECT_CATALOGERS",
    "ECOSYSTEM_INSTALLED_CATALOGERS",
]
