# Binary Classifiers

The **binary cataloger** (`glance/catalogers/binary/`) finds unmanaged ELF/PE binaries and extracts their version using a data-driven classifier system inspired by [Anchore Syft](https://github.com/anchore/syft/tree/main/syft/pkg/cataloger/binary).

## How it works

```
candidate path (from FileIndex)
     ↓
  Glob gate          file_globs match? (e.g. **/libcrypto.so*)
     ↓
  ELF precheck       first 4 bytes == \x7fELF? (optional)
     ↓
  Content read       mmap, no full copy
     ↓
  Byte regex         version_patterns → named group "version"
     ↓
  Identity           purl_template + cpe_templates
```

### Step 1: Glob gate (cheap)

Before reading a single byte, the Gate checks whether the file's path matches any classifier's `file_globs`. This filter runs on every candidate from the FileIndex and is the primary performance lever — only matching paths proceed.

```python
# gate.py
Gate(["**/libcrypto.so*", "**/openssl", "**/python*"])
```

### Step 2: Content scan (only gated files)

Matched files are opened with `mmap` and scanned with pre-compiled **byte** regexes. Byte regexes are used rather than text regexes because version strings in binaries live between null bytes and may not be valid UTF-8.

```python
# byte regex on binary content
re.search(rb"OpenSSL (?P<version>[0-9]+\.[0-9]+\.[0-9]+\w*)", data)
```

### Step 3: Identity attribution

The captured `version` group is substituted into `purl_template` and `cpe_templates`:

```
purl_template = "pkg:generic/openssl@{version}"
→  pkg:generic/openssl@1.1.1w

cpe_template  = "cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*"
→  cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*
```

## Classifier definition

Classifiers are defined in `glance/catalogers/binary/classifiers.py`:

```python
Classifier(
    cls="openssl",
    file_globs=[
        "**/libcrypto.so*",
        "**/libssl.so*",
        "**/libcrypto-*.dll",
        "**/libeay32.dll",
        "**/openssl",
    ],
    matcher=contents(rb"OpenSSL (?P<version>[0-9]+\.[0-9]+[0-9a-z.]*)\s"),
    package="openssl",
    purl_template="pkg:generic/openssl@{version}",
    cpe_templates=["cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*"],
)
```

## Matcher types

| Factory | When to use |
|---------|------------|
| `contents(pattern)` | Single byte-regex; most common |
| `any_of(*patterns)` | Match any of several patterns (OR) |
| `all_of(*patterns)` | All patterns must match (AND) — for supporting evidence |
| `branching(*branches)` | Different identity per sub-match (e.g. AWS-LC vs OpenSSL) |
| `filename_template(pattern)` | Version lives in the filename itself |
| `shared_library(pattern)` | Version extracted from a referenced `.so` |
| `supporting(primary, secondary)` | A neighbouring `VERSION` file strengthens the match |

## Primary vs. supporting evidence

When the same file matches multiple classifiers (e.g. both `openssl-binary` and `openssl-library` match `libcrypto.so`), the results are merged into one `Component` with multiple `Occurrence` entries. The first matching classifier's identity wins; subsequent matches add occurrences but don't create duplicates.

## Discovery

Before classifiers run, `discover_all()` builds the candidate `FileIndex`:

- **Linux** — `get_plocate(config)` validates the plocate binary and DB, then
  queries the DB with substring anchors derived from the classifier globs
  (e.g. `**/libcrypto.so*` → anchor `libcrypto.so`). Each anchor is queried in
  its own plocate call — plocate treats multiple patterns as AND (intersection),
  so one call per anchor is required for correct OR/union behaviour. Results are
  deduplicated. The glob gate is the sole authority on what enters the FileIndex.
  If plocate is not available, glance raises a `RuntimeError`.
- **Windows** — MFT enumeration via `FSCTL_ENUM_USN_DATA`; no index needed.

The gate runs on every path from every engine — so the discovery method only affects speed, never correctness.
