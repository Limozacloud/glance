# Output Formats

glance supports three output formats, selectable with `--format`.

## CycloneDX 1.6 (default)

```bash
glance --format cyclonedx --output sbom.json
```

Full [CycloneDX 1.6](https://cyclonedx.org/specification/overview/) JSON. Each component carries:

- `name`, `version`, `purl`, `cpe`
- `evidence.occurrences[].location` — exact file path (binary/ecosystem catalogers)
- `properties` — `glance:source`, `glance:managed`, `glance:found_by`, `glance:owned_by`
- `dependencies` graph (when ownership correlation ran)

**Use this format** to feed Grype, Trivy, osv-scanner, or any CycloneDX-aware tool.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": { "timestamp": "2025-06-01T12:00:00Z" },
  "components": [
    {
      "type": "library",
      "name": "openssl",
      "version": "3.2.4",
      "purl": "pkg:generic/openssl@3.2.4",
      "cpe": "cpe:2.3:a:openssl:openssl:3.2.4:*:*:*:*:*:*:*",
      "evidence": {
        "occurrences": [
          { "location": "C:\\Program Files\\Git\\mingw64\\bin\\libcrypto-3-x64.dll" }
        ]
      },
      "properties": [
        { "name": "glance:source",   "value": "binary" },
        { "name": "glance:managed",  "value": "false" },
        { "name": "glance:found_by", "value": "win_binary" }
      ]
    }
  ]
}
```

## Minimal

```bash
glance --format minimal --output findings.json
```

A flat JSON array — one object per component, no CycloneDX envelope. Designed for quick triage, dashboards, or piping into `jq`.

Fields: `name`, `version`, `purl`, `cpe` (if available), `path` (if available), `source`.

**Version format by ecosystem:**

| Source | `version` format | Example |
|---|---|---|
| RPM | `epoch:version-release` or `version-release` | `1:3.0.7-18.el9`, `3.0.7-18.el9` |
| DEB/APK | `version` | `3.0.11-1~deb12u2` |
| Binary | version extracted from file content | `3.2.4` |
| PyPI/npm/… | package manager version | `2.28.1` |

RPM packages include the epoch prefix (`1:`) when the package carries a non-zero epoch. Packages without an epoch field or with epoch `0` use the plain `version-release` form.

```json
[
  {
    "name": "openssl-libs",
    "version": "1:3.0.7-18.el9",
    "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-18.el9?epoch=1&arch=x86_64&distro=redhat-9",
    "cpe": "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*",
    "path": "/usr/lib64/libssl.so.3",
    "source": "rpm"
  },
  {
    "name": "requests",
    "version": "2.28.1",
    "purl": "pkg:pypi/requests@2.28.1",
    "source": "pip"
  }
]
```

```bash
# List all EOL OpenSSL finds
glance --catalogers binary --format minimal | \
  jq '[.[] | select(.name == "openssl" and (.version | startswith("1.")))]'
```

## Native

```bash
glance --format native --output native.json
```

glance's internal representation — useful for debugging or building custom post-processors. Schema may change between versions.

## Audit report

The audit report (`--report FILE`) is separate from the SBOM and records everything that *didn't* happen:

```json
{
  "engine_used": "plocate",
  "engine_reason": "plocate binary found, DB fresh (2.1h old)",
  "scanned_paths": ["/opt", "/usr/lib64"],
  "skipped": [
    {
      "target": "/mnt/backup",
      "reason": "config:exclude_fs_type",
      "detail": "nfs"
    }
  ],
  "catalogers": [
    { "name": "dpkg", "ran": true, "components_found": 842 },
    { "name": "rpm",  "ran": false, "detail": "not available on this host" }
  ],
  "files_considered": 12847,
  "files_read": 31,
  "duration_seconds": 4.2
}
```
