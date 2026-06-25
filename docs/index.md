# glance

**glance** is a mini-SBOM scanner for servers and workstations. It produces a [CycloneDX 1.6](https://cyclonedx.org/) JSON Software Bill of Materials in under a second — covering everything from OS packages to unmanaged bundled libraries buried inside application directories.

## What it finds

| Source | What | Examples |
|--------|------|---------|
| **OS packages** | Every installed package with its exact version | `openssl 3.0.13` via rpm/dpkg/apk |
| **Windows registry** | Installed applications from Uninstall keys | `Google Chrome 124.0`, `SQL Server 2019` |
| **PE binaries** | Bundled DLLs/EXEs via Windows VERSIONINFO | `curl 7.65.0` inside Insta360 Studio |
| **ELF binaries** | Unmanaged shared libraries via byte regex | `openssl 1.1.1w` bundled by an agent |
| **Ecosystem lock files** | Language-package dependencies | `requests==2.28.1` in requirements.txt |

Every find gets a **PURL** (`pkg:pypi/requests@2.28.1`) and where applicable a **CPE** (`cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*`) — the two identifiers vulnerability scanners like Grype and OSV need to correlate CVEs.

## Quick start

```bash
pip install glance
```

```bash
# Full scan — CycloneDX SBOM to stdout, audit report to file
glance --output sbom.json --report report.json

# Only Windows installed software (fast, no filesystem walk)
glance --catalogers software --format minimal

# Scan application directory for ecosystem lock files
glance --catalogers ecosystem --include /opt/myapp

# Feed directly into Grype
glance -o sbom.json && grype sbom:sbom.json
```

```python
from glance import scan, Config

result = scan(Config(include_paths=["/opt"]))
for c in result.components:
    print(c.name, c.version, c.purl)
```

## Sample output

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "library",
      "name": "openssl",
      "version": "1.1.0",
      "purl": "pkg:generic/openssl@1.1.0",
      "cpe": "cpe:2.3:a:openssl:openssl:1.1.0:*:*:*:*:*:*:*",
      "evidence": {
        "occurrences": [
          { "location": "C:\\Program Files\\Insta360 Studio\\libcryptoMD.dll" }
        ]
      },
      "properties": [
        { "name": "glance:source", "value": "binary" },
        { "name": "glance:managed", "value": "false" }
      ]
    }
  ]
}
```

!!! tip "OpenSSL 1.1.0 is EOL"
    OpenSSL 1.1.0 reached end-of-life in September 2019. glance surfaced it bundled inside a third-party application — something neither `rpm -qa` nor `pip list` would show.

## Key design decisions

- **No root required.** Runs with whatever permissions the invoking user has; skipped paths appear in the audit report.
- **Dependency-light.** The scan core uses only the Python standard library. PyYAML is optional (config files only).
- **Transparent skips.** Every path, filesystem, or cataloger that was *not* scanned is recorded with a reason. A "green" SBOM never silently omits 2 TB of network shares.
- **PURL + CPE for every component.** Feeds directly into Grype, osv-scanner, Trivy, and MSRC-based pipelines.
