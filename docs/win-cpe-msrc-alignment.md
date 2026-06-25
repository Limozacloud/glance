# Windows CPE ↔ limoza-vDB (MSRC) alignment

This note records the reconciliation of glance's Windows CPE detection against the
limoza-vDB Microsoft affected database (180 distinct `microsoft:*` products, derived from
MSRC CVRF). A scan only finds a CVE when the **CPE product string glance emits is identical
to the one the database stores** — so the two must use the same vocabulary.

## Where CPE detection lives (it is NOT one file)

| File | Scope |
|------|-------|
| `glance/data/win_cpe_index.yaml` | Registry / installed apps (SQL Server, Office, drivers, .NET, …) |
| `glance/data/win_binary_index.yaml` | PE binaries / bundled libs (openssl, …) |
| `glance/catalogers/binary/classifiers.py` | **Hardcoded** `cpe_templates` (python, golang, julia, …) |

`registry.py` and the binary cataloger do pure `{version}` template substitution — no
product-specific logic — so the Microsoft alignment is entirely a data change in
`win_cpe_index.yaml`.

## Fixed in this change

### SQL Server — the big one
The SQL build number already encodes the year in its major: `10.0`=2008, `11.0`=2012,
`12.0`=2014, `13.0`=2016, `14.0`=2017, `15.0`=2019, `16.0`=2022. So the year belongs in the
**build, not the product name**. MSRC's dominant form is `sql_server` + full build (824 rows),
not `sql_server_2019` (33 rows).

- before: `sql_server:2012` (year in version, no build) and `sql_server_2019:{build}`
- after:  **`sql_server:{version}`** (full build) for all of 2012/2014/2016/2017/2019/2022

Validated against the live DB for a SQL 2019 host `15.0.2000.5`:

```
sql_server_2019:15.0.2000.5   → 17 CVEs   (old form, only the 33-row product)
sql_server:15.0.2000.5        → 133 CVEs  (new form, the 824-row product)   ← 7.8×
sql_server:15.0.99999.0       → 0 CVEs    (top-current → no cross-year FP; introduced=major.minor
                                            scopes 15.0 away from 14.0/16.0 fixes)
```

### Office 2013
`office_2013` does not exist in the DB; Office 2013 sits under `office` (build `15.0.x`).
- before: `office_2013:{version}`  →  after: **`office:{version}`**
(`office_2016` / `office_2019` already match the DB and are unchanged.)

## Already aligned (no change needed)
`edge_chromium`, `.net`, `sharepoint_server`, `powershell`, `teams`, `defender_for_endpoint`,
`sql_server_management_studio`, `azure_data_studio`, `azure_connected_machine_agent`,
`office_2016`, `office_2019`, `project_2016`.

## Needs a limoza-vDB-side fix (glance is already correct)
glance emits the NVD/standard names; the DB drops MSRC's number-in-name variants and must
normalise them instead:

| glance (correct) | MSRC name in source | DB today |
|------------------|---------------------|----------|
| `odbc_driver_for_sql_server` | `odbc_driver_18_for_sql_server` | dropped (not in NVD dict) |
| `ole_db_driver_for_sql_server` | `ole_db_driver_19_for_sql_server` | dropped |

Fix belongs in `ingest/affected/cpe_norm.py`: add a candidate that strips an embedded
version token from the product (`odbc_driver_18_for_sql_server` → `odbc_driver_for_sql_server`)
before validating against the NVD dictionary.

## No DB coverage yet (left as-is — harmless, just no matches)
`visual_c++` (redist), `internet_information_services` (IIS), `silverlight`,
`local_administrator_password_solution` (LAPS), `office_2010`, `project_2019`.
MSRC does not track these as standalone affected products.

## Open decision — Office apps (excel / word / outlook / powerpoint / visio)
glance uses year-in-product (`excel_2016`); the DB uses **no year** (`excel`, 50 rows).
Switching glance to `excel` would gain coverage **but** risks cross-year false positives:
Office 2016/2019/2021 all share build major `16.0`, so the build alone can't separate the
years (unlike SQL). Left unchanged pending a DB-side decision on whether to year-scope the
Office app products. Tracked, not silently changed (to avoid introducing FPs).
