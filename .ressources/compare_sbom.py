"""SBOM comparator: glance (minimal format) vs syft (JSON format).

Usage:
    python .ressources/compare_sbom.py --glance scan_all.json --syft scan_syft.json
    python .ressources/compare_sbom.py --glance scan_all.json --syft scan_syft.json --output diff.json

Output (stdout): human-readable diff summary
Output (--output): machine-readable JSON with full diff details
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field

# --Normalised package --──────────────────────────────────────────────────────


@dataclass
class Pkg:
    name: str
    version: str
    purl: str
    cpes: list[str]
    paths: list[str]
    source: str  # "glance" | "syft"
    tool_source: str  # e.g. "registry", "binary", "dotnet", etc.


def _norm_name(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(" ", "").replace(".", "")


def _norm_ver(ver: str) -> str:
    return ver.strip().lstrip("v")


# --Loaders --─────────────────────────────────────────────────────────────────


def load_glance(path: str) -> list[Pkg]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data if isinstance(data, list) else data.get("components", [])
    pkgs: list[Pkg] = []
    for item in items:
        cpe = item.get("cpe", "")
        pkgs.append(
            Pkg(
                name=item.get("name", ""),
                version=_norm_ver(item.get("version", "")),
                purl=item.get("purl", ""),
                cpes=[cpe] if cpe else [],
                paths=[item["path"]] if item.get("path") else [],
                source="glance",
                tool_source=item.get("source", ""),
            )
        )
    return pkgs


def load_syft(path: str) -> list[Pkg]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    artifacts = data.get("artifacts", [])
    # deduplicate by (name, version) — syft emits one entry per location
    seen: dict[tuple[str, str], Pkg] = {}
    for item in artifacts:
        name = item.get("name", "")
        ver = _norm_ver(item.get("version", ""))
        key = (_norm_name(name), ver)
        cpes = [c["cpe"] for c in item.get("cpes", []) if isinstance(c, dict) and c.get("cpe")]
        locs = [loc.get("path", "") for loc in item.get("locations", []) if loc.get("path")]
        if key in seen:
            seen[key].paths.extend(locs)
            seen[key].paths = list(dict.fromkeys(seen[key].paths))
        else:
            seen[key] = Pkg(
                name=name,
                version=ver,
                purl=item.get("purl", ""),
                cpes=cpes,
                paths=locs,
                source="syft",
                tool_source=item.get("type", ""),
            )
    return list(seen.values())


# --Matching --────────────────────────────────────────────────────────────────


@dataclass
class Match:
    glance: Pkg
    syft: Pkg
    version_match: bool


@dataclass
class DiffResult:
    matched: list[Match] = field(default_factory=list)
    glance_only: list[Pkg] = field(default_factory=list)  # glance found, syft missed
    syft_only: list[Pkg] = field(default_factory=list)  # syft found, glance missed
    version_mismatch: list[Match] = field(default_factory=list)


def compare(glance_pkgs: list[Pkg], syft_pkgs: list[Pkg]) -> DiffResult:
    # Index syft by normalised name
    syft_by_name: dict[str, list[Pkg]] = {}
    for p in syft_pkgs:
        syft_by_name.setdefault(_norm_name(p.name), []).append(p)

    result = DiffResult()
    matched_syft_keys: set[int] = set()

    for gp in glance_pkgs:
        key = _norm_name(gp.name)
        candidates = syft_by_name.get(key, [])
        best: Pkg | None = None
        ver_match = False

        for sp in candidates:
            if sp.version == gp.version:
                best = sp
                ver_match = True
                break
            if best is None:
                best = sp

        if best is None:
            result.glance_only.append(gp)
        else:
            m = Match(glance=gp, syft=best, version_match=ver_match)
            matched_syft_keys.add(id(best))
            if ver_match:
                result.matched.append(m)
            else:
                result.version_mismatch.append(m)

    for sp in syft_pkgs:
        if id(sp) not in matched_syft_keys:
            result.syft_only.append(sp)

    return result


# --Reporting --───────────────────────────────────────────────────────────────


def print_report(diff: DiffResult, glance_total: int, syft_total: int) -> None:
    print(f"\n{'=' * 60}")
    print("  SBOM Comparison: glance vs syft")
    print(f"{'=' * 60}")
    print(f"  glance total (deduped) : {glance_total}")
    print(f"  syft total  (deduped)  : {syft_total}")
    print(f"  matched (name+version) : {len(diff.matched)}")
    print(f"  version mismatch       : {len(diff.version_mismatch)}")
    print(f"  glance only            : {len(diff.glance_only)}")
    print(f"  syft only (sample)     : {len(diff.syft_only)}")
    print(f"{'=' * 60}\n")

    if diff.glance_only:
        print(f"--glance found, syft missed ({len(diff.glance_only)}) --")
        for p in sorted(diff.glance_only, key=lambda x: x.name):
            cpe = p.cpes[0] if p.cpes else "-"
            print(f"  [{p.tool_source:12}] {p.name} {p.version}")
            print(f"             CPE: {cpe}")
        print()

    if diff.version_mismatch:
        print(f"--version mismatch ({len(diff.version_mismatch)}) --")
        for m in sorted(diff.version_mismatch, key=lambda x: x.glance.name):
            print(f"  {m.glance.name}: glance={m.glance.version}  syft={m.syft.version}")
        print()

    # syft_only: too many to list fully, show by type breakdown
    if diff.syft_only:
        by_type: dict[str, int] = {}
        for p in diff.syft_only:
            by_type[p.tool_source] = by_type.get(p.tool_source, 0) + 1
        print(f"--syft only: {len(diff.syft_only)} (breakdown by type) --")
        for t, cnt in sorted(by_type.items(), key=lambda x: -x[1]):
            print(f"  {t:20}: {cnt}")
        print()


# --Main --───────────────────────────────────────────────────────────────────


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare glance vs syft SBOM output")
    ap.add_argument("--glance", required=True, help="glance minimal JSON output")
    ap.add_argument("--syft", required=True, help="syft JSON output")
    ap.add_argument("--output", help="write full diff to this JSON file")
    args = ap.parse_args()

    glance_pkgs = load_glance(args.glance)
    syft_pkgs = load_syft(args.syft)

    diff = compare(glance_pkgs, syft_pkgs)
    print_report(diff, len(glance_pkgs), len(syft_pkgs))

    if args.output:

        def _ser(p: Pkg) -> dict:
            return asdict(p)

        out = {
            "summary": {
                "glance_total": len(glance_pkgs),
                "syft_total": len(syft_pkgs),
                "matched": len(diff.matched),
                "version_mismatch": len(diff.version_mismatch),
                "glance_only": len(diff.glance_only),
                "syft_only": len(diff.syft_only),
            },
            "glance_only": [_ser(p) for p in diff.glance_only],
            "version_mismatch": [
                {"glance": _ser(m.glance), "syft": _ser(m.syft)} for m in diff.version_mismatch
            ],
            "syft_only_sample": [_ser(p) for p in diff.syft_only[:200]],
        }
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=False)
        print(f"Full diff written to {args.output}")


if __name__ == "__main__":
    main()
