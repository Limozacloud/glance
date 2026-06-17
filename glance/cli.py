"""Command-line interface: ``glance`` / ``python -m glance``."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import __version__, scan
from .config import Config, Engine
from .output import report_to_dict, to_cyclonedx, to_native


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="glance",
        description="Mini-SBOM scanner: installed packages plus unmanaged binaries "
        "(found via locate gates) attributed to upstream PURL/CPE identities.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--config", metavar="FILE", help="YAML or JSON config file.")
    p.add_argument(
        "--engine",
        choices=[e.value for e in Engine],
        help="Override discovery engine (default: auto cascade).",
    )
    p.add_argument(
        "--include",
        action="append",
        metavar="PATH",
        help="Root path to scan (repeatable; overrides config include_paths).",
    )
    p.add_argument(
        "--catalogers",
        metavar="LIST",
        help="Comma-separated catalogers to run (e.g. binary,rpm,dpkg,apk).",
    )
    p.add_argument(
        "--format",
        choices=["cyclonedx", "native"],
        default="cyclonedx",
        help="SBOM output format (default: cyclonedx).",
    )
    p.add_argument("--output", "-o", metavar="FILE", help="Write the SBOM here (default: stdout).")
    p.add_argument("--report", metavar="FILE", help="Write the audit report JSON here.")
    p.add_argument("--log-level", default=None, help="Logging level (default: from config).")
    return p


def _make_config(args: argparse.Namespace) -> Config:
    config = Config.from_file(args.config) if args.config else Config()
    if args.engine:
        config.engine = Engine(args.engine)
    if args.include:
        config.include_paths = list(args.include)
    if args.catalogers:
        config.catalogers = [c.strip() for c in args.catalogers.split(",") if c.strip()]
    if args.log_level:
        config.log_level = args.log_level
    return config


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        config = _make_config(args)
    except (ValueError, OSError, ImportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(levelname)s %(name)s: %(message)s",
    )

    result = scan(config)

    if args.format == "cyclonedx":
        document = to_cyclonedx(result, __version__)
    else:
        document = to_native(result)
    text = json.dumps(document, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(report_to_dict(result.report), fh, indent=2)
            fh.write("\n")

    rep = result.report
    print(
        f"glance: {len(result.components)} components "
        f"(engine={rep.engine_used}, considered={rep.files_considered}, "
        f"read={rep.files_read}, skipped={len(rep.skipped)}, "
        f"{rep.duration_seconds:.2f}s)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
