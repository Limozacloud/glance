# glance

[![CI](https://github.com/Limozacloud/glance/actions/workflows/ci.yml/badge.svg)](https://github.com/Limozacloud/glance/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/Limozacloud/glance)](LICENSE)

A **mini-SBOM scanner** for Linux servers. It produces a compact
[CycloneDX](https://cyclonedx.org/) 1.6 SBOM from two kinds of evidence:

1. **Package catalogers** (`rpm`, `dpkg`, `apk`) enumerate every installed
   package with its full version and a proper `pkg:rpm`/`pkg:deb`/`pkg:apk` PURL.
2. **The binary cataloger** finds files via cheap *locate gates*, reads the
   version straight out of the bytes, and attributes the file to an upstream
   identity — e.g. a bundled `libcrypto.so.1.1` becomes `openssl 1.1.1w` with a
   `pkg:generic/openssl@1.1.1w` PURL **and** a versioned CPE.

## Install

```bash
pip install glance        # ships PyYAML; pure-stdlib core otherwise
```

Requires Python 3.10+. The scan logic uses only the standard library; PyYAML is
used only to read a YAML config file.

## Usage

### CLI

```bash
# scan the whole system, write a CycloneDX SBOM
glance --output sbom.json --report report.json

# only the binary cataloger, forced filesystem walk, narrow scope
glance --catalogers binary --engine walk --include /opt --include /usr/lib64

# feed straight into a vulnerability scanner
glance -o sbom.json && grype sbom:sbom.json
```

```
--config FILE        YAML or JSON config file
--engine ENGINE      auto | plocate | mlocate | walk   (default: auto)
--include PATH       root path to scan (repeatable)
--catalogers LIST    comma list: binary,rpm,dpkg,apk    (default: all applicable)
--format FORMAT      cyclonedx | native                 (default: cyclonedx)
--output, -o FILE    write the SBOM (default: stdout)
--report FILE        write the audit report JSON
```

### Library

```python
from glance import scan, Config

result = scan(Config(include_paths=["/opt", "/usr/lib64"]))

for c in result.components:
    print(c.name, c.version, c.purl, "managed" if c.managed else "UNMANAGED")

# audit trail — what ran, what was skipped, and why
print(result.report.engine_used, result.report.skipped)
```

Constructing `Config` in code needs no YAML — handy when embedding glance in a
larger agent.

## How it works

```
config -> discovery -> scanner (binary) ┐
                                         ├─> correlate -> models -> CycloneDX + report
          package catalogers (rpm/...)  ┘
```

1. **Glob gate first.** A path/filename glob (the union of all classifier gates,
   e.g. `**/libcrypto.so*`, `**/openssl`, `**/python*`) decides which files are
   interesting *before* any content is read.
2. **Discovery engine cascade.** `plocate` -> `mlocate` -> filesystem walk.
   locate is used only as a fast index returning a *superset*; the gate is the
   sole authority on what matches, so the engine choice only affects speed,
   never results. A staleness check (`max_db_age_hours`) drops a too-old DB out
   of the cascade. `mandatory_paths` (e.g. `/usr/lib64`, `/opt`) are **always**
   walked directly, regardless of engine, DB freshness or any customer
   `updatedb.conf` pruning.
3. **Content scan.** Only gated candidates are read, via `mmap` (no whole-file
   copies), and matched with pre-compiled **byte** regexes (version strings live
   between `\x00` separators).
4. **Correlation.** For each binary find, glance asks the package DBs *who owns
   this exact path?* Owned -> *managed*, suppressed in favour of the package
   component (recorded in the report). Unowned -> *unmanaged*, emitted as a
   `pkg:generic` component attributed to its install-path application.
5. **Audit report.** Every skipped path/filesystem/cataloger is recorded with a
   reason. A "green" scan can never silently mean "green, except the 2 TB nobody
   looked at."

## Configuration

A full, commented reference ships at
[`glance/data/default_config.yaml`](glance/data/default_config.yaml). All keys
are optional; the same defaults live in code. Present keys override the default,
absent keys keep it, and an unknown key is a hard error.

| key | default | meaning |
|-----|---------|---------|
| `include_paths` | `["/"]` | roots to scan (walk fallback / result bound) |
| `exclude_paths` | `[]` | extra path prefixes to skip |
| `exclude_fs_types` | nfs, cifs, tmpfs, overlay, … | filesystem types never scanned |
| `mandatory_paths` | `/usr/lib`, `/usr/lib64`, `/opt`, … | always walked, never prunable |
| `file_globs` | `null` (derive from classifiers) | the glob gate |
| `engine` | `auto` | `auto`/`plocate`/`mlocate`/`walk` |
| `max_db_age_hours` | `24` | a locate DB older than this is unusable |
| `on_stale_db` | `fallback` | `fallback` (cascade) or `warn` (use anyway) |
| `catalogers` | `null` (all applicable) | subset of `binary,rpm,dpkg,apk` |
| `correlate_ownership` | `true` | managed/unmanaged correlation |
| `max_file_size` | `209715200` | skip content scan above this many bytes |
| `elf_precheck` | `false` | gate on ELF magic (skips script tools if on) |
| `compute_sha256` | `false` | hash matched files |

## Adding a classifier

A classifier is **data**: a gate plus byte-regex matchers and identity
templates. Add one to `glance/catalogers/binary/classifiers.py`:

```python
from .matchers import Classifier, contents

Classifier(
    cls="nginx-binary",
    file_globs=["**/nginx"],
    # version strings sit between NULs in the binary
    matcher=contents(rb"(?m)nginx version: [^/]+/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
    package="nginx",
    purl_template="pkg:generic/nginx@{version}",
    cpe_templates=["cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*"],
)
```

`{version}` is substituted with the captured version in the PURL and CPE.
Richer matchers are available: `any_of`, `all_of`, `none_of`, `branching`
(pick an identity per sub-match, e.g. AWS-LC vs OpenSSL), `filename_template`
(version from the filename), `shared_library` (version from a referenced `.so`),
and `supporting` (a neighbouring `VERSION` file).

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
mypy glance
```

## License

MIT
