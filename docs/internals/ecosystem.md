# Ecosystem Catalogers

Ecosystem catalogers find **language-level dependencies** by parsing lock files. They walk `include_paths` looking for well-known manifest filenames and emit `pkg:pypi/...`, `pkg:npm/...`, etc. PURLs.

## Common behaviour (base class)

All ecosystem catalogers share `EcosystemCataloger` (`glance/catalogers/ecosystem/base.py`):

1. Walk each path in `self.paths` with `os.walk`.
2. Skip directories in `_SKIP_DIRS`: `.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `.tox`, `dist`, `build`.
3. For each file where `_is_manifest(filename)` is True, call `_parse_manifest(path)`.
4. Deduplicate by `(name.lower(), version.lower())` globally across all manifest files found.
5. Emit one `Component` per unique `(name, version)` pair, with an `Occurrence` pointing at the manifest file.

## Per-cataloger details

### pip

**Files:** `requirements.txt`, `requirements-dev.txt`, `requirements-test.txt`, `requirements-prod.txt`, `Pipfile.lock`

**requirements.txt** — only pinned (`==`) versions are captured. Unpinned (`>=`, `~=`, no operator) are ignored because they don't represent a specific installed version.

```
requests==2.28.1      ✓ captured
flask>=2.0            ✗ skipped (not pinned)
numpy                 ✗ skipped
```

**Pipfile.lock** — JSON format. Reads both `default` and `develop` sections. The `==` prefix on version strings is stripped.

PURL normalization: package names are lowercased and underscores replaced with hyphens (`Pillow` → `pkg:pypi/pillow@10.0.0`).

### go

**Files:** `go.sum`

Each line: `module version hash` or `module version/go.mod hash`.

The `/go.mod` lines are deduplicated — each module appears only once. The leading `v` is stripped from the version field (`v0.9.1` → `0.9.1`).

```
github.com/pkg/errors v0.9.1 h1:...      → pkg:golang/github.com/pkg/errors@0.9.1
github.com/pkg/errors v0.9.1/go.mod h1:... → deduplicated
```

### npm

**Files:** `package-lock.json`, `yarn.lock`

`package-lock.json` supports all lockfile versions:
- v1: reads `dependencies[name].version`
- v2/v3: reads `packages["node_modules/name"].version` (handles scoped packages like `@babel/core`)

`yarn.lock` is parsed line by line: entry headers give the package name, `version "x.y.z"` lines give the pinned version.

### nuget

**Files:** `packages.config`, `*.packages.lock.json`

`packages.config` is XML:
```xml
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" />
</packages>
```

`*.packages.lock.json` is JSON: reads `dependencies[framework][name].resolved` for each target framework.

### maven

**Files:** `pom.xml`

Reads `<dependency>` elements from `<dependencies>` sections. The component name is `groupId/artifactId`.

`${property}` version references (e.g. `${spring.version}`) are skipped — the component is emitted with `version=null` since the resolved version isn't knowable without the full Maven build.

### gem

**Files:** `Gemfile.lock`

Parses the `specs:` section under `GEM`:
```
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)         ← captured
    rake (13.0.6)         ← captured
```

Lines with 4-space indent and `name (version)` format are captured. Dependency constraint lines (8-space indent) are ignored.
