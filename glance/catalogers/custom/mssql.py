"""Windows registry reader for Microsoft SQL Server instances.

Reads the actual patch level per instance from:
  HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL
  → HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\<reg_root>\\Setup\\PatchLevel

This avoids the Uninstall key which produces multiple entries per installation
(one per component/feature) and keeps the RTM version (e.g. 15.0.2000.5)
permanently even after patching.
"""

from __future__ import annotations

from ...models import Component, ComponentType, Source

_HKLM = 0x80000002


def _fill(template: str, version: str) -> str:
    return template.replace("{version}", version or "*")


def _reg_str(key: object, value_name: str) -> str | None:
    try:
        import winreg

        val, _ = winreg.QueryValueEx(key, value_name)  # type: ignore[attr-defined,arg-type]
        return str(val).strip() if val else None
    except OSError:
        return None


HANDLES = {
    "sql_server_2012",
    "sql_server_2014",
    "sql_server_2016",
    "sql_server_2017",
    "sql_server_2019",
    "sql_server_2022",
}

_PREFIX_MAP = {
    "MSSQL11": "sql_server_2012",
    "MSSQL12": "sql_server_2014",
    "MSSQL13": "sql_server_2016",
    "MSSQL14": "sql_server_2017",
    "MSSQL15": "sql_server_2019",
    "MSSQL16": "sql_server_2022",
}

_INSTANCE_KEYS = [
    r"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL",
    r"SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL",
]


def _reg_str_at(winreg, hive: int, subkey: str, value_name: str) -> str | None:
    try:
        key = winreg.OpenKey(hive, subkey)
    except OSError:
        return None
    with key:
        return _reg_str(key, value_name)


def read(winreg, index_by_id: dict) -> list[Component]:
    components: list[Component] = []
    seen: set[tuple[str, str, str]] = set()

    for inst_key_path in _INSTANCE_KEYS:
        wow = "WOW6432Node\\" if "WOW6432" in inst_key_path else ""
        try:
            inst_key = winreg.OpenKey(_HKLM, inst_key_path)
        except OSError:
            continue
        with inst_key:
            i = 0
            while True:
                try:
                    inst_name, reg_root, _ = winreg.EnumValue(inst_key, i)
                except OSError:
                    break
                i += 1

                prefix = reg_root.split(".")[0]
                entry_id = _PREFIX_MAP.get(prefix)
                if not entry_id:
                    continue
                entry = index_by_id.get(entry_id)
                if not entry:
                    continue

                patch_level = _reg_str_at(
                    winreg,
                    _HKLM,
                    rf"SOFTWARE\{wow}Microsoft\Microsoft SQL Server\{reg_root}\Setup",
                    "PatchLevel",
                )
                if not patch_level:
                    continue

                dedup_key = (entry_id, inst_name, patch_level)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                purl = _fill(entry["purl_template"], patch_level)
                cpe = _fill(entry["cpe_template"], patch_level)
                components.append(
                    Component(
                        name=entry["name"],
                        version=patch_level,
                        type=ComponentType.APPLICATION,
                        source=Source.REGISTRY,
                        purl=purl,
                        cpes=[cpe],
                        bom_ref=purl,
                        managed=True,
                        metadata={
                            "display_name": f"SQL Server ({inst_name})",
                            "instance": inst_name,
                            "index_id": entry_id,
                        },
                    )
                )

    return components
