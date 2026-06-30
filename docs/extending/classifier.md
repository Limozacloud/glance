# Classifier Extensions

A classifier file teaches glance how to recognise software it does not know yet. The same file can cover all platforms: Linux/macOS binary scanning, Windows Registry matching, and Windows PE binary matching.

## Format

A YAML (or JSON) file with a top-level `classifiers` list. Each entry carries a `cataloger` field that routes it to the right engine:

| `cataloger` | Engine | Reads |
|---|---|---|
| `linux_binary` (default) | Binary cataloger | File contents via byte-regex |
| `windows_registry` | Registry cataloger | Registry DisplayName / Publisher |
| `windows_binary` | Win-binary cataloger | PE VERSIONINFO ProductName / CompanyName |

Omitting `cataloger` defaults to `linux_binary` (backward-compatible).

## Full example

```yaml
# /etc/glance/extra-classifiers.yaml
classifiers:

  # Linux/macOS — version extracted from file bytes
  - cataloger: linux_binary
    class: sap-hostagent-binary
    file_globs:
      - "**/saphostagent"
      - "**/sapstartsrv"
    version_patterns:
      - 'SAP Host Agent (?P<version>[0-9]+\.[0-9]+)'
    package: sap-hostagent
    purl: "pkg:generic/sap-hostagent@{version}"
    cpes:
      - "cpe:2.3:a:sap:host_agent:{version}:*:*:*:*:*:*:*"

  # Windows — match via Registry DisplayName / Publisher
  - cataloger: windows_registry
    id: sap-hostagent-registry
    display_name_contains:
      - SAP Host Agent
    publisher_contains:
      - SAP SE
    name: sap-hostagent
    purl_template: "pkg:generic/sap-hostagent@{version}"
    cpe_template: "cpe:2.3:a:sap:host_agent:{version}:*:*:*:*:*:*:*"

  # Windows — match via PE VERSIONINFO ProductName / CompanyName
  - cataloger: windows_binary
    id: sap-hostagent-pe
    product_name_contains:
      - SAP Host Agent
    company_contains:
      - SAP SE
    name: sap-hostagent
    purl_template: "pkg:generic/sap-hostagent@{version}"
    cpe_template: "cpe:2.3:a:sap:host_agent:{version}:*:*:*:*:*:*:*"
```

Register the file in your scan config:

```yaml
classifier_files:
  - /etc/glance/extra-classifiers.yaml
```

## `linux_binary` entry keys

| Key | Required | Description |
|---|---|---|
| `class` | yes | Unique classifier name |
| `file_globs` | yes | Glob patterns for the filename gate |
| `version_patterns` | yes* | Byte-regex list, first match wins. Named group `version` required. |
| `all_patterns` | yes* | AND-mode: all patterns must match (merges named groups) |
| `branches` | yes* | List of sub-classifiers, one identity per branch |
| `package` | no | Package name (used when `purl`/`purl_template` contain `{package}`) |
| `purl` / `purl_template` | no | PURL template — `{version}` is substituted |
| `cpes` / `cpe_templates` | no | CPE template list |

*One of `version_patterns`, `all_patterns`, or `branches` is required.

## `windows_registry` entry keys

| Key | Required | Description |
|---|---|---|
| `id` | yes | Unique identifier |
| `display_name_contains` | yes | Registry DisplayName substrings (case-insensitive OR) |
| `publisher_contains` | no | Registry Publisher substrings (case-insensitive OR) |
| `display_name_not_contains` | no | Exclusion substrings |
| `name` | yes | Component name in the SBOM |
| `purl_template` | yes | PURL template — `{version}` is substituted |
| `cpe_template` | no | CPE template |

## `windows_binary` entry keys

| Key | Required | Description |
|---|---|---|
| `id` | yes | Unique identifier |
| `product_name_contains` | yes | PE ProductName substrings (case-insensitive OR) |
| `company_contains` | no | PE CompanyName substrings (case-insensitive OR) |
| `name` | yes | Component name in the SBOM |
| `purl_template` | yes | PURL template — `{version}` is substituted |
| `cpe_template` | no | CPE template |

## Tips

### Finding the version string (linux_binary)

Run `strings <binary> | grep -E '[0-9]+\.[0-9]'` to find likely version strings. Common patterns:

```
OpenSSL 1.1.1w  11 Sep 2023
curl/8.4.0
Python 3.11.5
```

Test your regex on real bytes:

```python
import re, mmap

with open("/path/to/binary", "rb") as f:
    data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    m = re.search(rb"SAP Host Agent (?P<version>[0-9]+\.[0-9]+)", data)
    print(m.group("version") if m else "no match")
```

### CPE vendor/product

Look up the NVD CPE entry at [nvd.nist.gov/products/cpe/search](https://nvd.nist.gov/products/cpe/search). The vendor and product fields must match NVD exactly for CVE correlation to work.

### Glob gate accuracy (linux_binary)

- Prefer specific glob patterns over `**/*` — the gate is the primary performance filter.
- Include all likely filenames: `libcrypto.so*`, `libcrypto-*.dll`, `libeay32.dll`.
- `.so*` covers both `libcrypto.so` and `libcrypto.so.1.1`.

## In-code classifiers (linux_binary only)

For built-in classifiers that ship with glance, add a `Classifier` object directly to `glance/catalogers/binary/classifiers.py`:

```python
from .matchers import Classifier, contents

Classifier(
    cls="nginx-binary",
    file_globs=["**/nginx", "**/nginx-debug"],
    matcher=contents(
        rb"nginx version: [^/]+/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"
    ),
    package="nginx",
    purl_template="pkg:generic/nginx@{version}",
    cpe_templates=["cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*"],
)
```
