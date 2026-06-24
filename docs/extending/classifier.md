# Add a Binary Classifier

A classifier is **data**, not code. Adding support for a new binary means writing a `Classifier` object — no new Python files needed.

## In code

Add to `glance/catalogers/binary/classifiers.py`:

```python
from .matchers import Classifier, contents

Classifier(
    cls="nginx-binary",
    file_globs=["**/nginx", "**/nginx-debug"],
    matcher=contents(
        rb"nginx version: [^/]+/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"
    ),
    package="nginx",
    purl_template="pkg:generic/nginx@{version}",
    cpe_templates=["cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*"],
)
```

## Without touching code

Create a YAML file and point `classifier_files` at it:

```yaml
# /etc/glance/extra-classifiers.yaml
classifiers:
  - class: nginx-binary
    file_globs:
      - "**/nginx"
      - "**/nginx-debug"
    version_patterns:
      - 'nginx version: [^/]+/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)'
    package: nginx
    purl: "pkg:generic/nginx@{version}"
    cpes:
      - "cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*"
```

```yaml
# scan config
classifier_files:
  - /etc/glance/extra-classifiers.yaml
```

## Tips

### Finding the version string

Run `strings <binary> | grep -E '[0-9]+\.[0-9]'` to find likely version strings. Common patterns:

```
OpenSSL 1.1.1w  11 Sep 2023
curl/8.4.0
Python 3.11.5
```

Test your regex on real bytes:

```python
import re, mmap

with open("/path/to/binary", "rb") as f:
    data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    m = re.search(rb"nginx/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)", data)
    print(m.group("version") if m else "no match")
```

### CPE vendor/product

Look up the NVD CPE entry for the software at [nvd.nist.gov/products/cpe/search](https://nvd.nist.gov/products/cpe/search). The vendor and product fields must match NVD exactly for CVE correlation to work.

### Glob gate accuracy

- Prefer specific glob patterns over `**/*` — the gate is the primary performance filter.
- Include all likely filenames: `libcrypto.so*`, `libcrypto-*.dll`, `libeay32.dll`.
- `.so*` covers both `libcrypto.so` and `libcrypto.so.1.1`.
