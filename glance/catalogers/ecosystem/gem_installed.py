"""RubyGems installed packages cataloger — reads installed .gemspec files.

Ruby installs each gem with a <name>-<version>.gemspec file under a
`specifications/` directory, e.g.:
  /usr/lib/ruby/gems/3.0.0/specifications/rails-7.0.4.gemspec
  /var/lib/gems/3.0.0/specifications/rake-13.0.6.gemspec
  ~/.local/share/gem/ruby/3.0.0/specifications/sinatra-3.0.6.gemspec

Name and version are encoded directly in the filename — no Ruby parsing needed.
"""

from __future__ import annotations

import os
import re

from ...models import Source
from .base import EcosystemCataloger

# <gem-name>-<version>.gemspec  — version always starts with a digit.
# Greedy (.+) takes the longest possible name before the last -<digit> sequence.
_GEMSPEC_RE = re.compile(r"^(.+)-(\d[\w.+-]*)\.gemspec$")


class GemInstalledCataloger(EcosystemCataloger):
    name = "gem_installed"
    source = Source.GEM

    def manifest_filenames(self) -> list[str]:
        return [".gemspec"]  # substring match finds *.gemspec via by_name_substr

    def _is_manifest(self, filename: str) -> bool:
        return bool(_GEMSPEC_RE.match(filename))

    def _is_in_specifications(self, path: str) -> bool:
        return os.path.basename(os.path.dirname(path)) == "specifications"

    def _index_candidates(self, index) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for path in index.by_name_substr(".gemspec"):
            if path in seen:
                continue
            fname = os.path.basename(path)
            if not self._is_manifest(fname):
                continue
            if not self._is_in_specifications(path):
                continue
            seen.add(path)
            found.append(path)
        return found

    def _purl(self, name: str, version: str | None) -> str:
        v = version or "*"
        return f"pkg:gem/{name}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        m = _GEMSPEC_RE.match(os.path.basename(path))
        if m:
            return [(m.group(1), m.group(2))]
        return []
