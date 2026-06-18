"""Classifier validation against real binary snippets.

Each snippet is a small byte window captured from a real shared library on
Ubuntu 24.04, base64-encoded so the test needs no network or Docker — the same
approach Syft uses for its `testdata/snippets/`. Recapturing one:

    docker run --rm ubuntu:24.04 bash -c '
      apt-get update -qq && apt-get install -y -qq <pkg> >/dev/null
      so=$(dpkg -L <pkg> | grep -m1 "\\.so\\.[0-9]")
      off=$(grep -aboP "<marker>" "$so" | head -1 | cut -d: -f1)
      dd if="$so" bs=1 skip=$((off-40)) count=240 2>/dev/null | base64 -w0'
"""

from __future__ import annotations

import base64
import os

import pytest

from glance.catalogers.binary import BinaryCataloger
from glance.config import Config
from glance.models import ScanReport

# name: (filename on disk, base64 byte window, expected name, version, purl)
SNIPPETS = {
    "libtiff": (
        "libtiff.so.6",
        "VFdlYlBEYXRhc2V0V3JpdGVyAAAAAAAAAAAAAAAAAABMSUJUSUZGLCBWZXJzaW9uIDQuNS4xCkNvcHly"
        "aWdodCAoYykgMTk4OC0xOTk2IFNhbSBMZWZmbGVyCkNvcHlyaWdodCAoYykgMTk5MS0xOTk2IFNpbGlj"
        "b24gR3JhcGhpY3MsIEluYy4AAAAAAAAAVElGRlRpbGVTaXplAAAAAFRJRkZWVGlsZVNpemUAAABUSUZG"
        "VlRpbGVTaXplNjQAVElGRlRpbGVSb3dTaXplAFRJRkZUaWxlUm93U2l6ZTY0AAAAAAAAAA==",
        "libtiff",
        "4.5.1",
        "pkg:generic/libtiff@4.5.1",
    ),
    "libcurl": (
        "libcurl.so.4",
        "KnMlJTI1JXNdAHhuLS0ASW52YWxpZCB6b25laWQ6ICVzOyAlcwAmAGxpYmN1cmwvOC41LjAAemxpYi8l"
        "cwBsaWJpZG4yLyVzAGxpYnBzbC8lcwBsaWJzc2gvJXMAbmdodHRwMi8lcwBsaWJydG1wLyVkLiVkJXMA"
        "JXMvJXUuJXUuJXUAV09SS1NUQVRJT04AaW5jb21pbmcgTlRMTSBtZXNzYWdlIHRvbyBiaWcAJXMoJXMp"
        "AE9wZW5TU0wAU3dpdGNoIGZyb20gUE9TVCB0byBHRVQAU3dpdGNoIHRvICVzACVzOi8vJXMAVVJMIHJl",
        "curl",
        "8.5.0",
        "pkg:generic/curl@8.5.0",
    ),
    "expat": (
        "libexpat.so.1",
        "aGVkAGludmFsaWQgYXJndW1lbnQAcGFyc2VyIG5vdCBzdGFydGVkAGV4cGF0XzIuNi4xAHNpemVvZihY"
        "TUxfQ2hhcikAc2l6ZW9mKFhNTF9MQ2hhcikAWE1MX0RURABYTUxfQ09OVEVYVF9CWVRFUwBYTUxfTlMA"
        "WE1MX0JMQVBfTUFYX0FNUABYTUxfQkxBUF9BQ1RfVEhSRVMAWE1MX0dFAAAAAGV4cGF0OiBFbnRpdGll"
        "cyglcCk6IENvdW50ICU5ZCwgZGVwdGggJTJkLyUyZCAlKnMlcyVzOyAlcyBsZW5ndGggJWQgKHhtbHBh",
        "expat",
        "2.6.1",
        "pkg:generic/expat@2.6.1",
    ),
    "pcre2": (
        "libpcre2-8.so.0",
        "Wzo8Ol1dAFs6PjpdXQBRXEUAVkVSU0lPTgBERUZJTkUAMTQuMC4wADEwLjQyIDIwMjItMTItMTEAVVRG"
        "OCkAVVRGKQBVQ1ApAE5PVEVNUFRZKQBOT1RFTVBUWV9BVFNUQVJUKQBOT19BVVRPX1BPU1NFU1MpAE5P"
        "X0RPVFNUQVJfQU5DSE9SKQBOT19KSVQpAE5PX1NUQVJUX09QVCkATElNSVRfSEVBUD0ATElNSVRfTUFU"
        "Q0g9AExJTUlUX0RFUFRIPQBMSU1JVF9SRUNVUlNJT049AENSKQBBTlkpAEJTUl9BTllDUkxGKQBCU1Jf",
        "pcre2",
        "10.42",
        "pkg:generic/pcre2@10.42",
    ),
    "libssh": (
        "libssh.so.4",
        "AHNlc3Npb24AYXV0aC1hZ2VudEBvcGVuc3NoLmNvbQBTU0gtMi4wLWxpYnNzaF8wLjEwLjYAU1NILTIu"
        "MC0lcwANCgBCeWUgQnllAFJlcXVlc3QgbGVuZ3RoOiAldQBSZXNwb25zZSBsZW5ndGg6ICV1AE5vdCBl"
        "bm91Z2ggc3BhY2UAQXV0aGVudGljYXRpb24gc3VjY2Vzc2Z1bABSZWNlaXZlZCBTU0hfVVNFUkFVVEhf"
        "U1VDQ0VTUwBSZWNlaXZlZCBTU0hfUkVRVUVTVF9TVUNDRVNTAFJlY2VpdmVkIFNTSF9SRVFVRVNUX0ZB",
        "libssh",
        "0.10.6",
        "pkg:generic/libssh@0.10.6",
    ),
    "libpng": (
        "libpng16.so.16",
        "AAAAAAAAAAAAAAAAAAAAAAAAYmFkIGxvbmdqbXA6IAAxLjYuNDMAIGxpYnBuZyB2ZXJzaW9uIDEuNi40"
        "MwoKAHVuZXhwZWN0ZWQgemxpYiByZXR1cm4gY29kZQB1bmV4cGVjdGVkIGVuZCBvZiBMWiBzdHJlYW0A"
        "bWlzc2luZyBMWiBkaWN0aW9uYXJ5AHpsaWIgSU8gZXJyb3IAYmFkIHBhcmFtZXRlcnMgdG8gemxpYgBk"
        "YW1hZ2VkIExaIHN0cmVhbQBpbnN1ZmZpY2llbnQgbWVtb3J5AHVuc3VwcG9ydGVkIHpsaWIgdmVyc2lv",
        "libpng",
        "1.6.43",
        "pkg:generic/libpng@1.6.43",
    ),
    "libarchive": (
        "libarchive.so.13",
        "RjE2QkUAVVRGMTZMRQBhcmNoaXZlX3dyaXRlX2RhdGEAKG51bGwpAGxpYmFyY2hpdmUgMy43LjIAYXJj"
        "aGl2ZV93cml0ZV9jbG9zZQBUcnVuY2F0ZWQgYnppcDIgZmlsZSBib2R5AGJ6aXAyIGRlY29tcHJlc3Np"
        "b24gZmFpbGVkAHh6IGluaXRpYWxpemF0aW9uIGZhaWxlZCglZCkAVHJ1bmNhdGVkIHh6IGZpbGUgYm9k"
        "eQB4eiBkYXRhIGVycm9yIChlcnJvciAlZCkAeHogdW5rbm93biBlcnJvciAlZAB4eiBwcmVtYXR1cmUg",
        "libarchive",
        "3.7.2",
        "pkg:generic/libarchive@3.7.2",
    ),
}


@pytest.mark.parametrize("key", list(SNIPPETS))
def test_real_snippet(tmp_path, key):
    filename, b64, exp_name, exp_version, exp_purl = SNIPPETS[key]
    data = base64.b64decode(b64)
    path = tmp_path / "usr" / "lib" / filename
    os.makedirs(path.parent, exist_ok=True)
    path.write_bytes(data)

    comps = BinaryCataloger().catalog({str(path)}, Config(), ScanReport())
    assert len(comps) == 1, f"{key}: expected 1 component, got {len(comps)}"
    c = comps[0]
    assert c.name == exp_name
    assert c.version == exp_version
    assert c.purl == exp_purl
    assert c.cpes and exp_version in c.cpes[0]
