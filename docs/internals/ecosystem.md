# Ecosystem Catalogers

Ecosystem catalogers find **language-level dependencies**. They operate in two modes controlled by `ecosystem_mode` in config:

- **`installed`** (default) — reads actual install stores on disk. Use for server and container scans.
- **`project`** — reads lock and manifest files. Use for repository and CI scans.

The `--catalogers ecosystem` group alias resolves to the active mode. The explicit aliases `ecosystem-installed` and `ecosystem-project` always select a specific set regardless of config.

## Common behaviour (base class)

All ecosystem catalogers share `EcosystemCataloger` (`glance/catalogers/ecosystem/base.py`):

1. Candidates are found via a `FileIndex` built during the shared filesystem walk — no separate walk per cataloger.
2. Each cataloger queries the index by its manifest filename(s) and applies its own filtering logic.
3. Deduplicate by `(name.lower(), version.lower())` globally across all files found.
4. Emit one `Component` per unique `(name, version)` pair with an `Occurrence` pointing at the source file.

---

## Installed-level catalogers

### distinfo

**Reads:** `*.dist-info/METADATA` files  
**PURL:** `pkg:pypi/<name>@<version>` (name lowercased, `_` → `-`)

Covers everything pip, uv, poetry, and pipx install — system Python, user installs (`~/.local/lib/`), and any virtualenv anywhere on the scan path. Only packages that are actually installed leave a `.dist-info` directory.

Parses the RFC 822 header block: stops at the first blank line and reads `Name:` and `Version:` fields.

```
/usr/local/lib/python3.11/site-packages/requests-2.28.1.dist-info/METADATA
  → pkg:pypi/requests@2.28.1
```

### node_installed

**Reads:** `node_modules/*/package.json`  
**PURL:** `pkg:npm/<name>@<version>`

Reads `package.json` files that sit exactly one level below a `node_modules/` directory. Scoped packages (`@scope/pkg`) are handled — their `package.json` is two levels deep.

Only direct children of `node_modules` are cataloged, not the transitive dependency tree inside nested `node_modules/` subdirectories.

```
/app/node_modules/lodash/package.json            → pkg:npm/lodash@4.17.20
/app/node_modules/@babel/core/package.json       → pkg:npm/%40babel/core@7.21.0
```

### jar

**Reads:** `META-INF/maven/<groupId>/<artifactId>/pom.properties` inside `*.jar` files  
**PURL:** `pkg:maven/<groupId>/<artifactId>@<version>`

Opens each `.jar` as a ZIP and reads the embedded Maven coordinates. Every Maven-built JAR contains this file with exact `groupId`, `artifactId`, and `version` properties — more reliable than `pom.xml` which may contain unresolved property references.

```
/app/lib/log4j-core-2.14.1.jar
  META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties
  → pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
```

JARs that do not contain `pom.properties` (e.g. repackaged JARs, JVM runtime JARs) are silently skipped.

### gem_installed

**Reads:** `specifications/<name>-<version>.gemspec` filenames  
**PURL:** `pkg:gem/<name>@<version>`

Name and version are encoded directly in the filename — no Ruby parsing needed. Only `.gemspec` files inside a `specifications/` directory are considered (the standard gem install layout).

```
/usr/local/lib/ruby/gems/3.1.0/specifications/rack-2.2.6.gemspec
  → pkg:gem/rack@2.2.6
```

---

## Project-level catalogers

### pip

**Files:** `requirements.txt`, `requirements-dev.txt`, `requirements-test.txt`, `requirements-prod.txt`, `Pipfile.lock`

Only pinned (`==`) versions are captured. Unpinned (`>=`, `~=`, no operator) are ignored because they don't represent a specific installed version.

```
requests==2.28.1      ✓ captured
flask>=2.0            ✗ skipped (not pinned)
numpy                 ✗ skipped
```

`Pipfile.lock` — JSON format. Reads both `default` and `develop` sections. The `==` prefix on version strings is stripped.

PURL normalization: package names are lowercased and underscores replaced with hyphens (`Pillow` → `pkg:pypi/pillow@10.0.0`).

### go

**Files:** `go.sum`

Each line: `module version hash` or `module version/go.mod hash`.

The `/go.mod` lines are deduplicated — each module appears only once. The version field is used as-is, including the leading `v`.

```
github.com/pkg/errors v0.9.1 h1:...      → pkg:golang/github.com/pkg/errors@v0.9.1
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
