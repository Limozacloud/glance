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


def test_foreign_package_bundling_a_lib_is_surfaced():
    # a third-party deb owns a bundled openssl 1.1.1 (the agent-bundle case)
    comp = _openssl("/opt/acme-agent/lib/libcrypto.so.1.1")
    owner = "pkg:deb/ubuntu/acme-agent@1.25.0-1?arch=amd64"
    resolver = OwnershipResolver({"/opt/acme-agent/lib/libcrypto.so.1.1": owner})
    report = ScanReport()
    out = correlate([comp], resolver, report)
    assert len(out) == 1
    lib = out[0]
    assert lib.name == "openssl" and lib.version == "1.1.1w"
    assert lib.purl == "pkg:generic/openssl@1.1.1w"
    assert lib.managed is True  # owned by a package, but a foreign one
    assert lib.owned_by == owner
    assert any("bundled by" in c for c in report.correlations)


def test_same_product_deb_is_still_suppressed():
    # libcrypto.so.3 owned by libssl3 -> same product -> suppressed
    comp = _openssl("/usr/lib/x86_64-linux-gnu/libcrypto.so.3")
    owner = "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.25?arch=amd64"
    resolver = OwnershipResolver({"/usr/lib/x86_64-linux-gnu/libcrypto.so.3": owner})
    report = ScanReport()
    out = correlate([comp], resolver, report)
    assert out == []
    assert any("same product" in c for c in report.correlations)


def test_same_product_matching():
    from glance.correlate import _same_product

    assert _same_product("openssl", "pkg:deb/ubuntu/libssl3@3.0.2")
    assert _same_product("openssl", "pkg:rpm/rhel/openssl-libs@3.0.7")
    assert _same_product("libarchive", "pkg:deb/ubuntu/libarchive13@3.6.0")
    assert _same_product("xz", "pkg:deb/ubuntu/xz-utils@5.2.5")
    assert _same_product("python", "pkg:deb/ubuntu/python3.10-minimal@3.10.12")
    # foreign bundlers
    assert not _same_product("openssl", "pkg:deb/ubuntu/acme-agent@1.25.0")
    assert not _same_product("sqlite3", "pkg:deb/ubuntu/some-agent@1.0")
