# Catalogers & Groups

A **cataloger** is a self-contained component that discovers one class of software and returns a list of `Component` objects with PURL and CPE.

## Quick reference

```bash
# Run a group
glance --catalogers software          # OS packages only (fast)
glance --catalogers binary            # Bundled ELF/PE libraries
glance --catalogers ecosystem         # Language packages (mode: installed or project)
glance --catalogers all               # Everything

# Explicit ecosystem mode
glance --catalogers ecosystem-installed   # Actual install stores (dist-info, node_modules, JARs, gemspecs)
glance --catalogers ecosystem-project     # Lock / manifest files (requirements.txt, go.sum, …)

# Mix groups and individuals
glance --catalogers software,distinfo,jar
```

## Groups

| Group | Members | Notes |
|-------|---------|-------|
| `software` | `dpkg`, `rpm`, `apk`, `registry` | OS-level packages |
| `binary` | `binary`, `win_binary` | Bundled ELF/PE libraries |
| `ecosystem` | resolved by `ecosystem_mode` config | Default: `installed` set |
| `ecosystem-installed` | `distinfo`, `node_installed`, `jar`, `gem_installed`, `nuget` | Actual install stores |
| `ecosystem-project` | `pip`, `go`, `npm`, `nuget`, `maven`, `gem` | Lock/manifest files |
| `all` | everything above | Includes `gobinary` |

### `ecosystem` vs `ecosystem-installed` / `ecosystem-project`

`--catalogers ecosystem` is a **mode-aware alias**: it expands to either the installed-level or project-level set depending on `ecosystem_mode` in config (default: `installed`). Use the explicit group names to override regardless of config.

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
| `gobinary` | Go binaries (buildinfo, both pre-1.18 and 1.18+ formats) | `pkg:golang` | Any |

### Ecosystem catalogers — installed level

Read the actual install stores. Use these for server/container scans where you want to know what is genuinely deployed.

| Name | What it reads | PURL type | Notes |
|------|--------------|-----------|-------|
| `distinfo` | `*.dist-info/METADATA` | `pkg:pypi` | Everything pip/uv/poetry installs — venvs included |
| `node_installed` | `node_modules/*/package.json` | `pkg:npm` | Top-level packages only; scoped (`@scope/pkg`) supported |
| `jar` | `META-INF/maven/**/pom.properties` inside `*.jar` | `pkg:maven` | Reads `groupId/artifactId/version` directly from the JAR |
| `gem_installed` | `specifications/<name>-<version>.gemspec` | `pkg:gem` | Parses name and version from the filename |
| `nuget` | `packages.config`, `*.packages.lock.json` | `pkg:nuget` | Shared with project level |

### Ecosystem catalogers — project level

Read lock and manifest files. Use these for repository / CI scans where you want to audit declared dependencies.

| Name | Manifest files | PURL type | Notes |
|------|---------------|-----------|-------|
| `pip` | `requirements.txt`, `requirements-*.txt`, `Pipfile.lock` | `pkg:pypi` | Only pinned (`==`) versions |
| `go` | `go.sum` | `pkg:golang` | Version includes leading `v` (`v0.9.1`) |
| `npm` | `package-lock.json`, `yarn.lock` | `pkg:npm` | Lockfile v1/v2/v3; scoped packages |
| `nuget` | `packages.config`, `*.packages.lock.json` | `pkg:nuget` | |
| `maven` | `pom.xml` | `pkg:maven` | Skips `${property}` versions |
| `gem` | `Gemfile.lock` | `pkg:gem` | Parses `specs:` section |

## How `available()` works

Each cataloger has an `available()` method. If it returns `False`, the cataloger is skipped and recorded in the audit report as `"not available on this host"`. Examples:

- `RegistryCataloger` returns `False` on non-Windows
- `WinBinaryCataloger` returns `False` on non-Windows
- `DpkgCataloger` returns `False` if `/var/lib/dpkg/status` doesn't exist

When you specify `--catalogers software`, all four members are attempted — unavailable ones are simply skipped.
