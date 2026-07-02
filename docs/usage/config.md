# Configuration

glance accepts a YAML or JSON config file (`--config FILE`) or `Config` object in code. All keys are optional.

## Full reference

```yaml
# Paths to scan — ecosystem catalogers search here for manifests and install
# stores. On Linux the binary cataloger uses plocate (not these paths directly);
# on Windows it enumerates the MFT of all fixed drives.
# Default (Linux): ["/"]
# Default (Windows): all fixed drive letters, e.g. ["C:\\", "D:\\"]
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

# Glob gate: which filenames are interesting at all.
# null = derive automatically from classifier definitions (recommended).
file_globs: null

# ---------------------------------------------------------------------------
# Discovery engine (Linux: plocate required)
# ---------------------------------------------------------------------------

# Path to the plocate binary.
# null = search $PATH. A RuntimeError is raised if no binary is found.
# Set this when the agent ships a static plocate binary at a fixed path.
plocate_binary: /opt/limoza/bin/plocate

# Path to the plocate database.
# null = /var/lib/plocate/plocate.db. A RuntimeError is raised if missing.
locate_db_path: /var/lib/limoza/plocate.db

# ---------------------------------------------------------------------------
# Catalogers
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Content scan
# ---------------------------------------------------------------------------

# Skip content scan for files larger than this (bytes). Default: 200 MB.
max_file_size: 209715200

# Gate on ELF magic before running byte-regex scan.
# Useful when include_paths contains many script files.
elf_precheck: false

# Hash each matched file. Adds sha256 to occurrences.
compute_sha256: false

# Logging level: DEBUG, INFO, WARNING, ERROR
log_level: INFO
```

## Minimal example

```yaml
plocate_binary: /opt/limoza/bin/plocate
locate_db_path: /var/lib/limoza/plocate.db
catalogers:
  - ecosystem
  - binary
```

```bash
glance --config my-scan.yaml --output sbom.json
```

## Config in code

```python
from glance import Config, scan

config = Config(
    plocate_binary="/opt/limoza/bin/plocate",
    locate_db_path="/var/lib/limoza/plocate.db",
    catalogers=["ecosystem", "binary"],
    ecosystem_mode="installed",
)

result = scan(config)
```

`Config` is a Python dataclass — every YAML key maps directly to a field.
