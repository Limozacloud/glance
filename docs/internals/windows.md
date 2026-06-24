# Windows Catalogers

glance has two Windows-specific catalogers: `registry` and `win_binary`.

## RegistryCataloger

**Source:** `glance/catalogers/registry.py`  
**Data file:** `glance/data/win_cpe_index.yaml`

Reads the three Windows Uninstall registry hives:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` (64-bit installs)
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*` (32-bit installs)
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` (per-user installs)

For each key it reads `DisplayName`, `Publisher`, and `DisplayVersion`, then matches against `win_cpe_index.yaml` to produce a versioned CPE.

### win_cpe_index.yaml format

```yaml
- id: google_chrome
  display_name_contains:
    - "Google Chrome"
  publisher_contains:
    - "Google"
  name: google-chrome
  cpe_template: "cpe:2.3:a:google:chrome:{version}:*:*:*:*:*:*:*"
  purl_template: "pkg:generic/google-chrome@{version}"
```

- `display_name_contains` — list of substrings, case-insensitive, any must match
- `publisher_contains` — optional; if present, at least one must match in `Publisher`
- First matching entry wins

### Microsoft Office / SQL Server CPE format

Microsoft products use **year-in-product** CPE names to match MSRC advisories:

```
cpe:2.3:a:microsoft:office_2016:{build}:*:*:*:*:*:*:*
cpe:2.3:a:microsoft:sql_server_2019:{build}:*:*:*:*:*:*:*
```

This is intentional: MSRC patches reference `FixedBuild` values that are compared numerically against the version field. The NVD-style `office:2016` naming is **not** used.

## WinBinaryCataloger

**Source:** `glance/catalogers/win_binary.py`  
**Data file:** `glance/data/win_binary_index.yaml`

Walks PE binary files (`.dll`, `.exe`, `.sys`) in `include_paths` (default: `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`).

### Discovery pipeline

1. **Extension gate** — only `.dll`, `.exe`, `.sys` files proceed
2. **MZ magic check** — first 2 bytes must be `MZ` (PE magic)
3. **VERSIONINFO read** — via `ctypes.windll.version`:
   - `GetFileVersionInfoSizeW` → `GetFileVersionInfoW` → `VerQueryValueW`
   - Extracts: `ProductName`, `ProductVersion`, `CompanyName`, `FileVersion`
4. **Product match** — against `win_binary_index.yaml`
5. **Version normalization** — `_normalize_version()` strips MSVC suffixes and trailing `.0` from 4-part versions

### win_binary_index.yaml format

```yaml
- id: openssl
  product_name_contains:
    - "OpenSSL"
  company_contains:
    - "OpenSSL"
  name: openssl
  cpe_template: "cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*"
  purl_template: "pkg:generic/openssl@{version}"
```

- `product_name_contains` — any substring match on `ProductName` (case-insensitive)
- `company_contains` — optional; any match on `CompanyName`

### Version normalization

```python
"3.0.13.0"                → "3.0.13"      # trailing .0 stripped from 4-part
"1.64.0.0 (MSVC release)" → "1.64.0"      # suffix stripped, then trailing .0
"2.48.1.windows.1"        → "2.48.1"      # non-numeric suffix stripped
```

### Why VERSIONINFO instead of byte-regex?

On Windows, PE files carry structured `VERSIONINFO` resources with `ProductName`, `CompanyName`, and `ProductVersion` in a standardized format. This is:

- **More reliable** than byte-regex (version is in a known location, not scattered through the binary)
- **No false positives** from version strings in string tables or debug symbols
- **No dependency** — `ctypes.windll.version` is Windows stdlib
