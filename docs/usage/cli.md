# CLI Reference

## Synopsis

```
glance [OPTIONS]
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--config FILE` | — | YAML or JSON config file |
| `--include PATH` | from config | Root path to scan. Repeatable. Overrides config `include_paths`. |
| `--catalogers LIST` | all applicable | Comma-separated catalogers or group names (see below) |
| `--format FORMAT` | `cyclonedx` | Output format: `cyclonedx` / `native` / `minimal` |
| `--output FILE` | stdout | Write the SBOM here |
| `--report FILE` | — | Write the audit report JSON here |
| `--log-level LEVEL` | `INFO` | Logging verbosity |
| `--version` | — | Print version and exit |

## Cataloger groups

Pass a group name to `--catalogers` instead of listing individual catalogers:

| Group | Expands to |
|-------|-----------|
| `software` | `dpkg`, `rpm`, `apk`, `registry` |
| `binary` | `binary`, `win_binary` |
| `ecosystem` | resolved by `ecosystem_mode` config (default: installed set) |
| `ecosystem-installed` | `distinfo`, `node_installed`, `jar`, `gem_installed`, `nuget` |
| `ecosystem-project` | `pip`, `go`, `npm`, `nuget`, `maven`, `gem` |
| `all` | everything above, including `gobinary` |

Groups and individual names can be mixed: `--catalogers software,distinfo,jar`.

## Examples

```bash
# Full scan, CycloneDX to file, audit report alongside
glance --output sbom.json --report report.json

# Windows: installed software only (registry), fastest scan
glance --catalogers software --format minimal --output win_software.json

# Windows: full scan including bundled DLLs
glance --catalogers software,binary --output sbom.json

# Linux: narrow scope to /opt (plocate drives discovery)
glance --catalogers binary --include /opt --output sbom.json

# Scan a deployed application — installed packages (default ecosystem mode)
glance --catalogers ecosystem --include /opt/myapp --output app_sbom.json

# Scan a source repository — lock files and manifests
glance --catalogers ecosystem-project --include /src/myrepo --output repo_sbom.json

# Pipeline: scan then vulnerability-match
glance -o sbom.json && grype sbom:sbom.json
glance -o sbom.json && osv-scanner --sbom sbom.json

# Quick triage — one line per component, no CycloneDX envelope
glance --catalogers software --format minimal | jq '.[] | "\(.name) \(.version)"'
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime error (scan failed) |
| `2` | Configuration error |

## Stderr summary

After every scan, glance prints a one-line summary to **stderr**:

```
glance: 134 components (engine=plocate, considered=84312, read=49, skipped=3, 12.4s)
```

- `engine` — which discovery engine ran (`plocate` on Linux, `mft` on Windows)
- `considered` — files that passed the glob gate
- `read` — files whose content was actually read
- `skipped` — paths/filesystems not scanned (see `--report` for details)
