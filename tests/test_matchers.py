from __future__ import annotations

from glance.classifiers.core.matchers import (
    Classifier,
    MatcherContext,
    any_of,
    branching,
    contents,
    elf_needed,
    is_elf,
)
from glance.classifiers.linux_binary import default_classifiers


def _ctx(data: bytes, path: str = "/usr/bin/x") -> MatcherContext:
    return MatcherContext(path=path, data=data)


def test_openssl_version_on_real_byte_layout():
    # version string sits between NULs, as in a real libcrypto.so
    data = b"\x00" * 32 + b"\x00OpenSSL 1.1.1w  11 Sep 2023\x00" + b"\x00" * 8
    m = contents(
        rb"\x00OpenSSL (?P<version>[0-9]+\.[0-9]+\.[0-9]+([a-z]+|-alpha[0-9]|-beta[0-9]|-rc[0-9])?)"
    )
    result = m(Classifier("openssl", [], m), _ctx(data))
    assert result is not None
    assert result[0].version == "1.1.1w"


def test_openssl_handles_three_part_and_suffix():
    for raw, expected in [
        (b"\x00OpenSSL 3.0.13 ", "3.0.13"),
        (b"\x00OpenSSL 3.1.4'", "3.1.4"),
        (b"\x00OpenSSL 3.2.0-beta1 ", "3.2.0-beta1"),
    ]:
        m = contents(
            rb"\x00OpenSSL (?P<version>[0-9]+\.[0-9]+\.[0-9]+([a-z]+|-alpha[0-9]|-beta[0-9]|-rc[0-9])?)"
        )
        result = m(Classifier("openssl", [], m), _ctx(raw))
        assert result and result[0].version == expected


def test_no_match_returns_none():
    m = contents(rb"\x00OpenSSL (?P<version>[0-9.]+)")
    assert m(Classifier("openssl", [], m), _ctx(b"nothing here")) is None


def test_branching_picks_first_match_with_its_identity():
    aws = Classifier(
        "aws-lc",
        [],
        contents(rb"AWS-LC (?P<version>[0-9.]+)\)\x00"),
        package="aws-lc",
        purl_template="pkg:generic/aws-lc@{version}",
    )
    ssl = Classifier(
        "openssl",
        [],
        contents(rb"\x00OpenSSL (?P<version>[0-9.]+)"),
        package="openssl",
        purl_template="pkg:generic/openssl@{version}",
    )
    matcher = branching(aws, ssl)
    parent = Classifier("openssl-binary", ["**/openssl"], matcher)

    aws_data = b"\x00OpenSSL 1.1.1 (compatible; AWS-LC 1.69.0)\x00"
    res = matcher(parent, _ctx(aws_data))
    assert res and res[0].identity.package == "aws-lc"

    ssl_data = b"\x00OpenSSL 3.1.4\x00"
    res = matcher(parent, _ctx(ssl_data))
    assert res and res[0].identity.package == "openssl"


def test_any_of_first_wins():
    m = any_of(
        contents(rb"never-here (?P<version>[0-9.]+)"),
        contents(rb"node\.js/v(?P<version>[0-9.]+)"),
    )
    res = m(Classifier("node", [], m), _ctx(b"node.js/v22.9.0 build"))
    assert res and res[0].version == "22.9.0"


def test_filename_template_python():
    # libpython gate-style: version comes from the filename, content confirms it
    cls = next(c for c in default_classifiers() if c.cls == "python-binary-lib")
    data = b"\x003.11.2\x00"
    ctx = _ctx(data, path="/usr/lib/libpython3.11.so.1.0")
    res = cls.matcher(cls, ctx)
    assert res and res[0].version == "3.11.2"


def test_is_elf():
    assert is_elf(b"\x7fELF\x02\x01\x01")
    assert not is_elf(b"#!/bin/sh\n")


def test_elf_needed_safe_on_garbage():
    assert elf_needed(b"not an elf") == []
    assert elf_needed(b"\x7fELF" + b"\x00" * 8) == []


def test_all_default_classifiers_compile_and_have_identity():
    classifiers = default_classifiers()
    assert len(classifiers) >= 70
    for c in classifiers:
        assert c.file_globs, f"{c.cls} has no gate"
        assert callable(c.matcher)
