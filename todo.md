# glance — offene Aufgaben

## Sofort / nächster PR

### binary-Cataloger Windows-Guard
- Linux ELF binary cataloger hat keine `available()`-Guard für Windows
- Fix: `available()` in `BinaryCataloger` → `return sys.platform != "win32"`

### Built-in YAML → Python dicts (Nuitka-Kompatibilität)
- `glance/classifiers/win_registry_data.py` statt `win_registry_index.yaml`
- `glance/classifiers/win_binary_data.py` statt `win_binary_index.yaml`
- `yaml` aus Pflicht-Dependencies entfernen → nur noch optional
- Extension-Mechanismus: eine externe YAML-Datei mit Sections (`registry:`, `binary:`)
  geladen via `Config.extension_file`

## Mittelfristig

### Ecosystem Catalogers: Install-Store statt Lockfiles
- **npm**: `node_modules/*/package.json` statt `package-lock.json` / `yarn.lock`
  - Lockfiles haben `version="*"` für nicht-installierte peer/optional deps
- **Maven**: `~/.m2/repository/` statt `pom.xml`
  - pom.xml ohne `<version>` erbt aus Parent-BOM → unauflösbar ohne BOM-Walk

### Windows Registry
- **IIS**: `SOFTWARE\Microsoft\InetStp\VersionString` als custom reader
- **Exchange**: DisplayName-Filter in `win_registry_index` ergänzen
- **Unknown passthrough**: Entscheidung ob nicht-gematchte Uninstall-Einträge
  als generische Inventory-Items emittiert werden sollen

### OpenSSL Windows DLLs
- Globs `**/libcrypto-*.dll`, `**/libssl-*.dll` in `win_binary_index` ergänzen

## Offen / Konzept

### VDB Match
- Vuln-Scan nach Merge #12 wiederholen (sauberer Stand mit MFT)
- Syft-Vergleich: gleicher Scope (alle Laufwerke), Ergebnisse gegenüberstellen
