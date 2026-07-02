# glance

[![CI](https://github.com/Limozacloud/glance/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Limozacloud/glance/actions/workflows/ci.yml?query=branch%3Amain)
[![License](https://img.shields.io/github/license/Limozacloud/glance)](LICENSE)

A **mini-SBOM scanner** for servers and containers. It produces a compact
[CycloneDX](https://cyclonedx.org/) 1.6 SBOM from multiple evidence sources:

1. **OS package catalogers** (`rpm`, `dpkg`, `apk`) enumerate every installed
   package with its full version and a proper `pkg:rpm`/`pkg:deb`/`pkg:apk` PURL.
2. **Ecosystem catalogers** read actual install stores (`dist-info`, `node_modules`,
   JARs, gemspecs) or project lock files — switchable via `ecosystem_mode`.
3. **The binary cataloger** finds files via a plocate index, reads the version
   straight out of the bytes, and attributes the file to an upstream identity —
   e.g. a bundled `libcrypto.so.1.1` becomes `openssl 1.1.1w` with a
   `pkg:generic/openssl@1.1.1w` PURL **and** a versioned CPE.

## Install

```bash
pip install glance        # ships PyYAML; pure-stdlib core otherwise
```

Requires Python 3.10+. The scan logic uses only the standard library; PyYAML is
used only to read a YAML config file.

## Prerequisites

### Linux

glance requires **plocate** with a pre-built database. The agent is responsible
for deploying the binary and running `updatedb` before glance is called. If
plocate is not found, glance raises a `RuntimeError`.

```bash
# build the database (once, or on a schedule)
/opt/limoza/bin/updatedb \
  --output /var/lib/limoza/plocate.db \
  --config-file /opt/limoza/etc/updatedb.conf \
  -l 0   # no group requirement

# run glance — it queries the pre-built DB
glance --config /opt/limoza/etc/glance.yaml --output sbom.json
```

By default glance looks for `plocate` in `$PATH` and the DB at
`/var/lib/plocate/plocate.db`. Use `plocate_binary` and `locate_db_path` in the
config to point at custom paths (e.g. a statically compiled binary shipped with
the agent).

### Windows

No prerequisites. glance enumerates the NTFS MFT directly (no index needed).

## Usage

### CLI

```bash
# scan the whole system, write a CycloneDX SBOM
glance --output sbom.json --report report.json

# only the binary cataloger, narrow to a specific path
glance --catalogers binary --include /opt --include /usr/lib64 --output sbom.json

# feed straight into a vulnerability scanner
glance -o sbom.json && grype sbom:sbom.json
```

```
--config FILE        YAML or JSON config file
--include PATH       root path to scan (repeatable)
--catalogers LIST    groups: software, binary, ecosystem, ecosystem-installed,
                     ecosystem-project, all
                     individuals: dpkg, rpm, apk, registry, binary, win_binary,
                     gobinary, distinfo, node_installed, jar, gem_installed,
                     pip, go, npm, nuget, maven, gem
--format FORMAT      cyclonedx | native | minimal       (default: cyclonedx)
--output, -o FILE    write the SBOM (default: stdout)
--report FILE        write the audit report JSON
```

### Library

```python
from glance import scan, Config

result = scan(Config(
    plocate_binary="/opt/limoza/bin/plocate",
    locate_db_path="/var/lib/limoza/plocate.db",
))

for c in result.components:
    print(c.name, c.version, c.purl, "managed" if c.managed else "UNMANAGED")

# audit trail — what ran, what was skipped, and why
print(result.report.engine_used, result.report.skipped)
```

Constructing `Config` in code needs no YAML — handy when embedding glance in a
larger agent.

## How it works

```
config → discovery (plocate / MFT) → FileIndex
                                          ↓
                               binary cataloger (byte-regex)
                                          ↓
         package catalogers (rpm/dpkg/…) → correlate → ScanResult + report
         ecosystem catalogers (pip/go/…) ↗
```

### Linux

1. **plocate query.** `get_plocate(config)` locates the binary (`plocate_binary`
   or `$PATH`) and the DB (`locate_db_path` or `/var/lib/plocate/plocate.db`).
   If either is missing a `RuntimeError` is raised — there is no walk fallback.
2. **Substring anchors.** Each classifier's glob (e.g. `**/libcrypto.so*`) is
   reduced to its longest literal fragment (`libcrypto.so`). Each anchor is
   queried in a separate plocate call (plocate treats multiple patterns as AND);
   results are deduplicated into a superset.
3. **Gate + scope filter.** Every path from plocate is checked against the glob
   gate, `exclude_paths`, and `exclude_fs_types`. Only matching paths enter the
   FileIndex.
4. **Content scan.** Only gated candidates are read, via `mmap`, and matched with
   pre-compiled **byte** regexes.
5. **Correlation.** For each binary find, glance asks the package DBs *who owns
   this exact path?* Owned → *managed*, suppressed in favour of the package
   component. Unowned → *unmanaged*, emitted as a `pkg:generic` component
   attributed to its install-path application.
6. **Audit report.** Every skipped path/filesystem/cataloger is recorded with a
   reason. A "green" scan never silently means "green, except the 2 TB nobody
   looked at."

### Windows

1. **MFT enumeration.** `mft.query()` enumerates NTFS master file table records
   directly (`FSCTL_ENUM_USN_DATA`) — no index needed. All fixed local drives are
   covered.
2. The rest (gate, content scan, correlation) is identical to Linux.

## Configuration

A full reference ships at
[`glance/default_config.yaml`](glance/default_config.yaml). All keys are
optional; defaults live in code. Present keys override the default, absent keys
keep it, and an unknown key is a hard error.

| key | default | meaning |
|-----|---------|---------|
| `plocate_binary` | `null` | path to plocate; `null` searches `$PATH` |
| `locate_db_path` | `null` | path to plocate DB; `null` uses `/var/lib/plocate/plocate.db` |
| `exclude_paths` | `[]` | path prefixes never scanned |
| `exclude_fs_types` | nfs, cifs, tmpfs, overlay, … | filesystem types never scanned |
| `file_globs` | `null` (derive from classifiers) | the glob gate |
| `catalogers` | `null` (all applicable) | group or individual cataloger names |
| `ecosystem_mode` | `installed` | `installed` (dist-info/node_modules/JARs/gemspecs) or `project` (lock files) |
| `correlate_ownership` | `true` | managed/unmanaged correlation |
| `classifier_files` | `[]` | extra YAML/JSON classifier definitions (no code change) |
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

### …or without touching code

Define classifiers in an external YAML/JSON file and point `classifier_files`
at it — they are loaded in addition to the built-ins:

```yaml
# extra-classifiers.yaml
classifiers:
  - class: nginx-library
    file_globs: ["**/libnginx.so*"]
    version_patterns:
      - 'nginx version: [^/]+/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)'
    package: nginx
    purl: "pkg:generic/nginx@{version}"
    cpes: ["cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*"]
```

```yaml
# scan config
classifier_files:
  - /etc/glance/extra-classifiers.yaml
```

`all_patterns` (AND) and `branches` (one identity per sub-match) are also
supported for the less common cases.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
mypy glance
```

## License

MIT
