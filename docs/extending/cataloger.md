# Add a Cataloger

A cataloger is a Python class with three methods. Use this path when none of the existing extension points (classifiers, CPE index) fit — e.g. a new OS package format or a new language ecosystem.

## Minimal interface

```python
class MyCataloger:
    name = "myformat"               # used in --catalogers and audit report

    def available(self) -> bool:
        """Return True if this cataloger can run on the current host."""
        return True

    def catalog(self, report: ScanReport) -> list[Component]:
        """Discover components and append a CatalogerStatus to report."""
        components = []
        # ... your logic ...
        report.catalogers.append(CatalogerStatus(self.name, True, len(components)))
        return components

    def file_index(self) -> dict[str, str]:
        """Return {absolute_path → purl} for ownership correlation. {} if N/A."""
        return {}
```

## Ecosystem cataloger (recommended base)

For language package managers, inherit from `EcosystemCataloger`:

```python
from glance.catalogers.ecosystem.base import EcosystemCataloger
from glance.models import Source

class CargoCataloger(EcosystemCataloger):
    name = "cargo"
    source = Source.CARGO  # add CARGO = "cargo" to models.Source first

    def _is_manifest(self, filename: str) -> bool:
        return filename == "Cargo.lock"

    def _purl(self, name: str, version: str | None) -> str:
        v = version or "*"
        return f"pkg:cargo/{name}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        # parse Cargo.lock TOML format
        # return [(name, version), ...]
        ...
```

The base class handles walking, skipping non-interesting directories, deduplication, and status reporting. You only implement `_is_manifest`, `_purl`, and `_parse_manifest`.

## Adding a Source enum value

In `glance/models.py`:

```python
class Source(str, Enum):
    ...
    CARGO = "cargo"
```

## Registering the cataloger

### As a package cataloger (no path needed)

In `glance/catalogers/__init__.py`:

```python
from .mycataloger import MyCataloger

PACKAGE_CATALOGERS = {
    ...
    "myformat": MyCataloger,
}
```

`scan()` will instantiate it with `cataloger_cls()` — no arguments.

### As an ecosystem cataloger (needs paths)

In `glance/catalogers/ecosystem/__init__.py`:

```python
from .cargo import CargoCataloger

ECOSYSTEM_CATALOGERS = {
    ...
    "cargo": CargoCataloger,
}
```

`scan()` will instantiate it and call `catalog(report, index=file_index)` — the FileIndex (built by plocate/MFT) is passed in so the cataloger queries it for manifest files.

### Update the `ecosystem` group

In `glance/catalogers/__init__.py`, the `ecosystem` group is auto-populated from `ECOSYSTEM_CATALOGERS` — no manual update needed.

## Writing tests

Follow the pattern in `tests/test_ecosystem_catalogers.py`:

```python
def _catalog(cataloger_cls, tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    cat = cataloger_cls(paths=[str(tmp_path)])
    report = ScanReport()
    return cat.catalog(report)

def test_cargo_lock(tmp_path):
    content = '[[package]]\nname = "serde"\nversion = "1.0.189"\n'
    comps = _catalog(CargoCataloger, tmp_path, {"Cargo.lock": content})
    assert comps[0].name == "serde"
    assert comps[0].version == "1.0.189"
    assert comps[0].purl == "pkg:cargo/serde@1.0.189"
```
