from __future__ import annotations

from glance import _glob
from glance.discovery.gate import Gate, derive_globs


def test_doublestar_crosses_separators():
    assert _glob.match("**/libcrypto.so*", "/usr/lib64/libcrypto.so.1.1")
    assert _glob.match("**/libssl.so*", "/lib/x86_64-linux-gnu/libssl.so.3")
    assert _glob.match("**/openssl", "/usr/bin/openssl")


def test_single_star_does_not_cross_separator():
    assert _glob.match("**/python*", "/usr/bin/python3.11")
    assert not _glob.match("**/python*", "/usr/bin/python3.11/extra")


def test_brace_alternation():
    assert _glob.match("**/{go,go.exe}", "/usr/local/go/bin/go")
    assert _glob.match("**/{go,go.exe}", "/tmp/go.exe")
    assert _glob.match("**/{mariadb,mysql}", "/usr/bin/mysql")
    assert not _glob.match("**/{mariadb,mysql}", "/usr/bin/postgres")


def test_question_mark_fixed_width():
    assert _glob.match("**/libstd-????????????????.so", "/x/libstd-0123456789abcdef.so")
    assert not _glob.match("**/libstd-????????????????.so", "/x/libstd-short.so")


def test_no_false_positive_on_unrelated_files():
    assert not _glob.match("**/openssl", "/etc/passwd")
    assert not _glob.match("**/libcrypto.so*", "/usr/lib/libc.so.6")


def test_backslash_paths_normalised():
    assert _glob.match("**/openssl", r"C:\tmp\usr\bin\openssl")


def test_gate_dedup_and_match():
    gate = Gate(["**/openssl", "**/openssl", "**/libssl.so*"])
    assert gate.globs == ["**/openssl", "**/libssl.so*"]
    assert gate.matches("/usr/bin/openssl")


def test_derive_globs_from_classifiers():
    from glance.catalogers.binary.classifiers import default_classifiers

    globs = derive_globs(default_classifiers())
    assert "**/openssl" in globs
    assert "**/libcrypto.so*" in globs  # glance enhancement
    assert len(globs) == len(set(globs))  # deduped
