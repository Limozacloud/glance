"""Windows registry reader for .NET runtimes and .NET Framework.

.NET Runtime (5+):
  HKLM\\SOFTWARE\\Microsoft\\ASP.NET Core\\Shared Framework\\v{major}.{minor}\\{version}
  Subkey names are exact patch versions (e.g. 8.0.17, 9.0.6).
  Matches the Greenbone NASL approach.

.NET Framework (1.x–4.x):
  HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\{vX.Y}\\Version
  Single Version value per major branch (e.g. 4.8.09221, 3.5.30729.4926).

Both avoid the Uninstall key which produces MSI-internal version numbers
and false negatives.
"""

from __future__ import annotations

from ...models import Component, ComponentType, Source

HANDLES = {"dotnet_runtime", "dotnet_framework"}

_HKLM = 0x80000002

_SHARED_FW_KEYS = [
    r"SOFTWARE\Microsoft\ASP.NET Core\Shared Framework",
    r"SOFTWARE\WOW6432Node\Microsoft\ASP.NET Core\Shared Framework",
]

# NDP subkeys to check for .NET Framework; v4\Full is the authoritative 4.x entry
_NDP_PATHS = [
    (r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full", "4"),
    (r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5",   "3.5"),
    (r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727", "2.0"),
]


def _fill(template: str, version: str) -> str:
    return template.replace("{version}", version or "*")


def _reg_str(winreg, path: str, value_name: str) -> str | None:
    try:
        key = winreg.OpenKey(_HKLM, path)
    except OSError:
        return None
    with key:
        try:
            val, _ = winreg.QueryValueEx(key, value_name)
            return str(val).strip() if val else None
        except OSError:
            return None


def _read_runtime(winreg, entry: dict, components: list, seen: set) -> None:
    for base_path in _SHARED_FW_KEYS:
        try:
            base_key = winreg.OpenKey(_HKLM, base_path)
        except OSError:
            continue
        with base_key:
            i = 0
            while True:
                try:
                    major_minor = winreg.EnumKey(base_key, i)  # e.g. "v8.0"
                except OSError:
                    break
                i += 1
                try:
                    mm_key = winreg.OpenKey(base_key, major_minor)
                except OSError:
                    continue
                with mm_key:
                    j = 0
                    while True:
                        try:
                            version = winreg.EnumKey(mm_key, j)  # e.g. "8.0.17"
                        except OSError:
                            break
                        j += 1
                        if version in seen:
                            continue
                        seen.add(version)
                        purl = _fill(entry["purl_template"], version)
                        cpe = _fill(entry["cpe_template"], version)
                        components.append(Component(
                            name=entry["name"],
                            version=version,
                            type=ComponentType.APPLICATION,
                            source=Source.REGISTRY,
                            purl=purl,
                            cpes=[cpe],
                            bom_ref=purl,
                            managed=True,
                            metadata={
                                "display_name": f".NET Runtime {version}",
                                "index_id": "dotnet_runtime",
                            },
                        ))


def _read_framework(winreg, entry: dict, components: list, seen: set) -> None:
    for ndp_path, major_hint in _NDP_PATHS:
        install = _reg_str(winreg, ndp_path, "Install")
        if install != "1":
            continue
        version = _reg_str(winreg, ndp_path, "Version")
        if not version or version in seen:
            continue
        seen.add(version)
        purl = _fill(entry["purl_template"], version)
        cpe = _fill(entry["cpe_template"], version)
        components.append(Component(
            name=entry["name"],
            version=version,
            type=ComponentType.APPLICATION,
            source=Source.REGISTRY,
            purl=purl,
            cpes=[cpe],
            bom_ref=purl,
            managed=True,
            metadata={
                "display_name": f".NET Framework {version}",
                "index_id": "dotnet_framework",
            },
        ))


def read(winreg, index_by_id: dict) -> list[Component]:
    components: list[Component] = []

    runtime_entry = index_by_id.get("dotnet_runtime")
    if runtime_entry:
        _read_runtime(winreg, runtime_entry, components, seen=set())

    framework_entry = index_by_id.get("dotnet_framework")
    if framework_entry:
        _read_framework(winreg, framework_entry, components, seen=set())

    return components
