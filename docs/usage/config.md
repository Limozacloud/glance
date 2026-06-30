# Configuration

glance accepts a YAML or JSON config file (`--config FILE`) or `Config` object in code. All keys are optional.

## Full reference

```yaml
# Paths to scan — the binary cataloger walks these for ELF/PE files;
# ecosystem catalogers search here for manifests and install stores.
# Default (Linux): ["/"]
# Default (Windows): all mounted drive letters, e.g. ["C:\\", "D:\\", "E:\\"]
include_paths:
  - /opt
  - /usr/lib64

# Path prefixes to always skip.
exclude_paths:
  - /proc
  - /sys
  - /run

# Filesystem types never scanned (prevents accidentally reading NFS mounts).
exclude_fs_types:
  - nfs
  - cifs
  - tmpfs
  - overlay
  - devtmpfs
  - sysfs
  - proc

# Always walked directly, even if the locate DB prunes them.
# These are cheap (small) and must never be missed.
mandatory_paths:
  - /usr/lib
  - /usr/lib64
  - /usr/local/lib
  - /opt

# Glob gate: which filenames are interesting at all.
# null = derive automatically from classifier definitions (recommended).
file_globs: null

# Discovery engine for binary scanning (Linux).
# auto: try plocate → mlocate → walk
# plocate / mlocate / walk: force a specific engine
engine: auto

# If the locate DB is older than this, treat it as unusable (cascade to next engine).
max_db_age_hours: 24

# What to do when the DB is stale: fallback (cascade) or warn (use anyway).
on_stale_db: fallback

# Which catalogers to run. null = all applicable.
# Accepts individual names or group aliases (software, binary, ecosystem,
# ecosystem-installed, ecosystem-project, all).
catalogers: null

# Controls which ecosystem catalogers the "ecosystem" group alias resolves to.
#   installed (default) — reads actual install stores: dist-info, node_modules,
#                         JARs (pom.properties), gemspecs. Use for server/container scans.
#   project             — reads lock/manifest files: requirements.txt, go.sum,
#                         package-lock.json, pom.xml, Gemfile.lock. Use for repo/CI scans.
ecosystem_mode: installed

# Correlate binary finds against package DBs to mark them managed/unmanaged.
correlate_ownership: true

# Classifier extension files — teach glance to recognise additional software.
# Each file may contain entries for any cataloger (linux_binary, windows_registry,
# windows_binary) in a single list using the "cataloger" field.
# See docs/extending/classifier.md for the full format.
classifier_files: []

# Legacy Windows-only extension file (registry.entries + binary.entries sections).
# Prefer classifier_files with cataloger: windows_registry / windows_binary instead.
extension_file: null

# Follow symlinks during filesystem walk. Default: false.
follow_symlinks: false

# Use a specific locate DB instead of probing standard paths. null = probe.
locate_db_path: null

# Skip content scan for files larger than this (bytes). Default: 200 MB.
max_file_size: 209715200

# Gate on ELF magic before running byte-regex scan.
# Useful when include_paths contains many script files.
elf_precheck: false

# Hash each matched file. Adds sha256 to occurrences.
compute_sha256: false

# Logging level: DEBUG, INFO, WARNING, ERROR
log_level: INFO

# ---------------------------------------------------------------------------
# Windows-specific
# ---------------------------------------------------------------------------

# PE file extensions scanned by win_binary.
win_pe_extensions:
  - .dll
  - .exe
  - .sys

# Discovery engine for Windows binary scanning: auto | mft | walk
win_binary_engine: auto
```

## Minimal example

```yaml
include_paths:
  - /opt/apps
catalogers:
  - ecosystem
  - binary
```

```bash
glance --config my-scan.yaml --output sbom.json
```

## Config in code

```python
from glance import Config, Engine

config = Config(
    include_paths=["/opt/apps"],
    catalogers=["ecosystem", "binary"],
    ecosystem_mode="installed",   # "project" for repo scans
    engine=Engine.WALK,
    max_db_age_hours=48,
)
```

`Config` is a Python dataclass — every YAML key maps directly to a field.
