"""Serialize the audit :class:`ScanReport`.

Enum members are ``str`` subclasses, so ``dataclasses.asdict`` + ``json`` emit
their values directly — no custom encoder needed.
"""

from __future__ import annotations

import dataclasses

from ..models import ScanReport


def report_to_dict(report: ScanReport) -> dict:
    return dataclasses.asdict(report)
