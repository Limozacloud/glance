# Add a CPE Entry (Windows Registry)

The Windows registry cataloger matches installed applications against `glance/data/win_cpe_index.yaml`. Adding a new application means adding one YAML entry — no Python required.

## Entry format

```yaml
- id: your_unique_id          # snake_case, unique across the file
  display_name_contains:
    - "Exact Product Name"    # substring(s) to match against DisplayName
    - "Alternate Name"        # (optional) additional variants
  publisher_contains:         # (optional) narrow by Publisher field
    - "Vendor Corp"
  name: product-name          # kebab-case, used in PURL
  cpe_template: "cpe:2.3:a:vendor:product:{version}:*:*:*:*:*:*:*"
  purl_template: "pkg:generic/product-name@{version}"
```

- `display_name_contains` — at least one substring must appear in `DisplayName` (case-insensitive)
- `publisher_contains` — if present, at least one must appear in `Publisher` (case-insensitive). Omit to match any publisher.
- `{version}` is replaced with `DisplayVersion` from the registry, or `*` if absent.

## Finding the DisplayName

On a Windows machine where the software is installed:

```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, Publisher, DisplayVersion |
  Sort-Object DisplayName
```

## Finding the CPE vendor/product

1. Search [nvd.nist.gov/products/cpe/search](https://nvd.nist.gov/products/cpe/search) for the product.
2. Copy the `vendor:product` pair from an existing CVE's CPE.
3. For Microsoft products, check MSRC — they use year-in-product names like `sql_server_2019`, not `sql_server:2019`.

## Example: adding Notepad++

```yaml
- id: notepad_plus_plus
  display_name_contains:
    - "Notepad++"
  name: notepad-plus-plus
  cpe_template: "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:{version}:*:*:*:*:*:*:*"
  purl_template: "pkg:generic/notepad-plus-plus@{version}"
```

Note: the `+` characters in the CPE product field must be escaped as `\\+\\+` in YAML (they are literal `\+\+` in the CPE string, which is how the NVD encodes them).

## Testing locally

```python
from glance.catalogers.registry import _index, _match

index = _index()
entry = next(e for e in index if e["id"] == "your_unique_id")

# Simulate what the registry would report
print(_match("Your Product Name 3.0", "Vendor Corp", entry))  # True/False
```

## What NOT to add

- Customer-specific or vendor-internal software (not in NVD/MSRC)
- Software with no public CVE history (no value for vuln correlation)
- Overly broad patterns that could match unrelated software
