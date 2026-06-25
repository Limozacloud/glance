# Catalogers & Groups

A **cataloger** is a self-contained component that discovers one class of software and returns a list of `Component` objects with PURL and CPE.

## Quick reference

```bash
# Run a group
glance --catalogers software          # OS packages only (fast)
glance --catalogers binary            # Bundled ELF/PE libraries
glance --catalogers ecosystem         # Language package lock files
glance --catalogers all               # Everything

# Mix groups and individuals
glance --catalogers software,pip

# Individual catalogers
glance --catalogers dpkg,pip,go
```

## Groups

| Group | Members | Platform |
|-------|---------|----------|
| `software` | `dpkg`, `rpm`, `apk`, `registry` | Any |
| `binary` | `binary`, `win_binary` | Any |
| `ecosystem` | `pip`, `go`, `npm`, `nuget`, `maven`, `gem` | Any |
| `all` | Everything | Any |

## Individual catalogers

### OS package managers

| Name | What it reads | PURL type | Platform |
|------|--------------|-----------|----------|
| `dpkg` | `/var/lib/dpkg/status` | `pkg:deb` | Linux (Debian/Ubuntu) |
| `rpm` | RPM database via `rpm -qa` | `pkg:rpm` | Linux (RHEL/CentOS/SUSE) |
| `apk` | `/lib/apk/db/installed` | `pkg:apk` | Linux (Alpine) |
| `registry` | Windows Uninstall registry keys | `pkg:generic` | Windows |

### Binary catalogers

| Name | What it reads | PURL type | Platform |
|------|--------------|-----------|----------|
| `binary` | ELF binaries via byte-regex classifiers | `pkg:generic` | Linux |
| `win_binary` | PE binaries via VERSIONINFO API | `pkg:generic` | Windows |

### Ecosystem catalogers

These walk `include_paths` looking for lock/manifest files.

| Name | Manifest files | PURL type | Notes |
|------|---------------|-----------|-------|
| `pip` | `requirements.txt`, `requirements-*.txt`, `Pipfile.lock` | `pkg:pypi` | Only pinned (`==`) versions |
| `go` | `go.sum` | `pkg:golang` | Deduplicates `/go.mod` lines |
| `npm` | `package-lock.json`, `yarn.lock` | `pkg:npm` | Supports lockfile v1/v2/v3 |
| `nuget` | `packages.config`, `*.packages.lock.json` | `pkg:nuget` | |
| `maven` | `pom.xml` | `pkg:maven` | Skips `${property}` versions |
| `gem` | `Gemfile.lock` | `pkg:gem` | Parses `specs:` section |

## How `available()` works

Each cataloger has an `available()` method. If it returns `False`, the cataloger is skipped and recorded in the audit report as `"not available on this host"`. Examples:

- `RegistryCataloger` returns `False` on non-Windows
- `WinBinaryCataloger` returns `False` on non-Windows
- `DpkgCataloger` returns `False` if `/var/lib/dpkg/status` doesn't exist

When you specify `--catalogers software`, all four members are attempted — unavailable ones are simply skipped.
