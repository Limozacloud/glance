from __future__ import annotations

from glance.correlate import OwnershipResolver, correlate
from glance.models import Component, ComponentType, Occurrence, ScanReport, Source


def _openssl(path: str) -> Component:
    return Component(
        name="openssl",
        version="1.1.1w",
        type=ComponentType.LIBRARY,
        source=Source.BINARY,
        purl="pkg:generic/openssl@1.1.1w",
        occurrences=[Occurrence(path=path, found_by="openssl-binary")],
    )


def test_managed_find_is_suppressed():
    comp = _openssl("/usr/lib64/libcrypto.so.3")
    resolver = OwnershipResolver(
        {"/usr/lib64/libcrypto.so.3": "pkg:rpm/rhel/openssl-libs@3.0.7-1.el9"}
    )
    report = ScanReport()
    out = correlate([comp], resolver, report)
    assert out == []  # represented by the rpm package component instead
    assert report.correlations and "managed by" in report.correlations[0]


def test_unmanaged_find_becomes_app_plus_library():
    comp = _openssl("/opt/acme-agent/lib/libcrypto.so.1.1")
    report = ScanReport()
    out = correlate([comp], OwnershipResolver({}), report)
    apps = [c for c in out if c.type == ComponentType.APPLICATION]
    libs = [c for c in out if c.type == ComponentType.LIBRARY]
    assert len(apps) == 1 and len(libs) == 1
    assert apps[0].name == "/opt/acme-agent/lib"
    assert libs[0].managed is False
    assert libs[0].bom_ref in apps[0].depends_on
    assert libs[0].owned_by == apps[0].bom_ref


def test_unmanaged_system_lib_has_no_app_wrapper():
    comp = _openssl("/usr/lib64/libcrypto.so.3")
    report = ScanReport()
    out = correlate([comp], OwnershipResolver({}), report)  # nobody owns it
    assert all(c.type == ComponentType.LIBRARY for c in out)
    assert out[0].managed is False


def test_correlation_disabled_keeps_everything_unmanaged():
    comp = _openssl("/usr/lib64/libcrypto.so.3")
    resolver = OwnershipResolver({"/usr/lib64/libcrypto.so.3": "pkg:rpm/rhel/openssl-libs@3.0.7"})
    report = ScanReport()
    out = correlate([comp], resolver, report, enabled=False)
    assert len(out) == 1 and out[0].managed is False
    assert not report.correlations


def test_same_version_managed_and_unmanaged_split():
    comp = _openssl("/usr/lib64/libcrypto.so.3")
    comp.occurrences.append(Occurrence(path="/opt/agent/libcrypto.so.3", found_by="openssl-binary"))
    resolver = OwnershipResolver({"/usr/lib64/libcrypto.so.3": "pkg:rpm/rhel/openssl-libs@3.0.7"})
    report = ScanReport()
    out = correlate([comp], resolver, report)
    # managed /usr/lib64 occurrence suppressed; /opt/agent one wrapped as app
    libs = [c for c in out if c.type == ComponentType.LIBRARY]
    assert len(libs) == 1
    assert libs[0].occurrences[0].path == "/opt/agent/libcrypto.so.3"
