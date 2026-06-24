# Python API

glance exposes a single public function: `scan()`.

## Basic usage

```python
from glance import scan, Config

result = scan(Config(include_paths=["/opt", "/usr/lib64"]))

for c in result.components:
    print(c.name, c.version, c.purl, c.managed)
```

## `scan(config)` → `ScanResult`

```python
from glance import scan, Config, Engine

result = scan(Config(
    include_paths=["/opt/myapp"],
    catalogers=["ecosystem", "binary"],   # groups expand automatically
    engine=Engine.WALK,
))
```

**Returns** a `ScanResult`:

```python
result.components   # list[Component]
result.report       # ScanReport — audit trail
result.timestamp    # float — unix timestamp
```

## `Component`

```python
c.name          # str   — e.g. "openssl"
c.version       # str | None
c.type          # ComponentType — APPLICATION or LIBRARY
c.source        # Source — rpm, dpkg, apk, registry, binary, pip, go, npm, …
c.purl          # str | None — pkg:generic/openssl@1.1.1w
c.cpes          # list[str] — versioned CPE strings
c.managed       # bool | None — True if owned by a package manager
c.occurrences   # list[Occurrence] — where it was found (path + evidence)
c.metadata      # dict — cataloger-specific extras
```

## `ScanReport`

```python
report = result.report

report.engine_used        # str — "plocate", "walk", None
report.engine_reason      # str — why this engine was chosen
report.scanned_paths      # list[str]
report.skipped            # list[SkippedEntry] — what was NOT scanned and why
report.catalogers         # list[CatalogerStatus] — per-cataloger run status
report.files_considered   # int
report.files_read         # int
report.duration_seconds   # float
report.warnings           # list[str]
```

## Serialization

```python
from glance.output import to_cyclonedx, to_minimal, to_native, report_to_dict
import json

# CycloneDX 1.6 JSON
bom = to_cyclonedx(result)
json.dumps(bom, indent=2)

# Flat list: [{name, version, purl, cpe, path, source}]
flat = to_minimal(result)
json.dumps(flat, indent=2)

# Audit report
rep = report_to_dict(result.report)
json.dumps(rep, indent=2)
```

## Embedding in an agent

glance is designed to be embedded. The library has no side effects outside of `scan()` — no global state, no file writes, no network calls:

```python
from glance import scan, Config

def collect_sbom(app_dir: str) -> dict:
    result = scan(Config(
        include_paths=[app_dir],
        catalogers=["ecosystem", "win_binary", "registry"],
    ))
    from glance.output import to_cyclonedx
    return to_cyclonedx(result)
```
