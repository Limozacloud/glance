"""Tests for ecosystem (language package manager) catalogers."""

from __future__ import annotations

import json
import textwrap
import zipfile
from pathlib import Path

from glance.catalogers import expand_catalogers
from glance.catalogers.ecosystem.distinfo import DistInfoCataloger
from glance.catalogers.ecosystem.gem import GemCataloger
from glance.catalogers.ecosystem.gem_installed import GemInstalledCataloger
from glance.catalogers.ecosystem.go import GoCataloger
from glance.catalogers.ecosystem.jar import JarCataloger
from glance.catalogers.ecosystem.maven import MavenCataloger
from glance.catalogers.ecosystem.node_installed import NodeInstalledCataloger
from glance.catalogers.ecosystem.npm import NpmCataloger
from glance.catalogers.ecosystem.nuget import NugetCataloger
from glance.catalogers.ecosystem.pip import PipCataloger
from glance.models import ScanReport, Source

# ── helpers ───────────────────────────────────────────────────────────────────


def _catalog(cataloger_cls, tmp_path: Path, files: dict[str, str]) -> list:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    cat = cataloger_cls(paths=[str(tmp_path)])
    report = ScanReport()
    return cat.catalog(report)


# ── PipCataloger ──────────────────────────────────────────────────────────────


def test_pip_requirements_txt(tmp_path):
    comps = _catalog(
        PipCataloger,
        tmp_path,
        {"requirements.txt": "requests==2.28.1\nflask>=2.0\n# comment\nnumpy==1.24.0\n"},
    )
    names = {c.name: c.version for c in comps}
    assert names["requests"] == "2.28.1"
    assert names["numpy"] == "1.24.0"
    assert "flask" not in names  # unpinned, skipped


def test_pip_purl_normalised(tmp_path):
    comps = _catalog(PipCataloger, tmp_path, {"requirements.txt": "Pillow==10.0.0\n"})
    assert comps[0].purl == "pkg:pypi/pillow@10.0.0"
    assert comps[0].source == Source.PIP


def test_pip_pipfile_lock(tmp_path):
    data = {
        "default": {"requests": {"version": "==2.28.1"}},
        "develop": {"pytest": {"version": "==7.4.0"}},
    }
    comps = _catalog(PipCataloger, tmp_path, {"Pipfile.lock": json.dumps(data)})
    names = {c.name: c.version for c in comps}
    assert names["requests"] == "2.28.1"
    assert names["pytest"] == "7.4.0"


def test_pip_skips_node_modules(tmp_path):
    comps = _catalog(
        PipCataloger, tmp_path, {"node_modules/somelib/requirements.txt": "requests==2.28.1\n"}
    )
    assert comps == []


def test_pip_deduplicates(tmp_path):
    comps = _catalog(
        PipCataloger,
        tmp_path,
        {
            "app/requirements.txt": "requests==2.28.1\n",
            "lib/requirements.txt": "requests==2.28.1\n",
        },
    )
    assert len(comps) == 1


# ── GoCataloger ───────────────────────────────────────────────────────────────


def test_go_sum_basic(tmp_path):
    content = textwrap.dedent("""\
        github.com/pkg/errors v0.9.1 h1:abc=
        github.com/pkg/errors v0.9.1/go.mod h1:xyz=
        golang.org/x/sys v0.21.0 h1:def=
    """)
    comps = _catalog(GoCataloger, tmp_path, {"go.sum": content})
    names = {c.name: c.version for c in comps}
    assert names["github.com/pkg/errors"] == "v0.9.1"
    assert names["golang.org/x/sys"] == "v0.21.0"


def test_go_purl(tmp_path):
    content = "github.com/stretchr/testify v1.8.4 h1:abc=\n"
    comps = _catalog(GoCataloger, tmp_path, {"go.sum": content})
    assert comps[0].purl == "pkg:golang/github.com/stretchr/testify@v1.8.4"
    assert comps[0].source == Source.GO


def test_go_deduplicates_gomod_lines(tmp_path):
    content = textwrap.dedent("""\
        github.com/pkg/errors v0.9.1 h1:abc=
        github.com/pkg/errors v0.9.1/go.mod h1:xyz=
    """)
    comps = _catalog(GoCataloger, tmp_path, {"go.sum": content})
    assert len(comps) == 1


# ── NpmCataloger ─────────────────────────────────────────────────────────────


def test_npm_package_lock_v2(tmp_path):
    data = {
        "lockfileVersion": 2,
        "packages": {
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/@babel/core": {"version": "7.18.6"},
        },
    }
    comps = _catalog(NpmCataloger, tmp_path, {"package-lock.json": json.dumps(data)})
    names = {c.name: c.version for c in comps}
    assert names["lodash"] == "4.17.21"
    assert names["@babel/core"] == "7.18.6"


def test_npm_package_lock_v1(tmp_path):
    data = {
        "lockfileVersion": 1,
        "dependencies": {"lodash": {"version": "4.17.21"}},
    }
    comps = _catalog(NpmCataloger, tmp_path, {"package-lock.json": json.dumps(data)})
    assert comps[0].version == "4.17.21"
    assert comps[0].source == Source.NPM


def test_npm_purl(tmp_path):
    data = {"lockfileVersion": 1, "dependencies": {"express": {"version": "4.18.2"}}}
    comps = _catalog(NpmCataloger, tmp_path, {"package-lock.json": json.dumps(data)})
    assert comps[0].purl == "pkg:npm/express@4.18.2"


def test_npm_yarn_lock(tmp_path):
    content = textwrap.dedent("""\
        # yarn lockfile v1

        lodash@^4.17.0:
          version "4.17.21"
          resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
    """)
    comps = _catalog(NpmCataloger, tmp_path, {"yarn.lock": content})
    assert len(comps) == 1
    assert comps[0].name == "lodash"
    assert comps[0].version == "4.17.21"


# ── NugetCataloger ────────────────────────────────────────────────────────────


def test_nuget_packages_config(tmp_path):
    xml = textwrap.dedent("""\
        <?xml version="1.0" encoding="utf-8"?>
        <packages>
          <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />
          <package id="Serilog" version="2.12.0" />
        </packages>
    """)
    comps = _catalog(NugetCataloger, tmp_path, {"packages.config": xml})
    names = {c.name: c.version for c in comps}
    assert names["Newtonsoft.Json"] == "13.0.1"
    assert names["Serilog"] == "2.12.0"


def test_nuget_lock_json(tmp_path):
    data = {
        "dependencies": {
            "net8.0": {
                "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"},
            }
        }
    }
    comps = _catalog(NugetCataloger, tmp_path, {"MyApp.packages.lock.json": json.dumps(data)})
    assert comps[0].name == "Newtonsoft.Json"
    assert comps[0].version == "13.0.3"
    assert comps[0].source == Source.NUGET


def test_nuget_purl(tmp_path):
    xml = '<packages><package id="Serilog" version="2.12.0" /></packages>'
    comps = _catalog(NugetCataloger, tmp_path, {"packages.config": xml})
    assert comps[0].purl == "pkg:nuget/Serilog@2.12.0"


# ── MavenCataloger ────────────────────────────────────────────────────────────


def test_maven_pom_xml(tmp_path):
    xml = textwrap.dedent("""\
        <?xml version="1.0"?>
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <dependencies>
            <dependency>
              <groupId>org.springframework</groupId>
              <artifactId>spring-core</artifactId>
              <version>5.3.20</version>
            </dependency>
            <dependency>
              <groupId>junit</groupId>
              <artifactId>junit</artifactId>
              <version>4.13.2</version>
            </dependency>
          </dependencies>
        </project>
    """)
    comps = _catalog(MavenCataloger, tmp_path, {"pom.xml": xml})
    names = {c.name: c.version for c in comps}
    assert names["org.springframework/spring-core"] == "5.3.20"
    assert names["junit/junit"] == "4.13.2"


def test_maven_skips_property_versions(tmp_path):
    xml = textwrap.dedent("""\
        <?xml version="1.0"?>
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <dependencies>
            <dependency>
              <groupId>org.foo</groupId>
              <artifactId>bar</artifactId>
              <version>${bar.version}</version>
            </dependency>
          </dependencies>
        </project>
    """)
    comps = _catalog(MavenCataloger, tmp_path, {"pom.xml": xml})
    assert len(comps) == 1
    assert comps[0].version is None


def test_maven_purl(tmp_path):
    xml = textwrap.dedent("""\
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <dependencies>
            <dependency>
              <groupId>com.google.guava</groupId>
              <artifactId>guava</artifactId>
              <version>32.1.2-jre</version>
            </dependency>
          </dependencies>
        </project>
    """)
    comps = _catalog(MavenCataloger, tmp_path, {"pom.xml": xml})
    assert comps[0].purl == "pkg:maven/com.google.guava/guava@32.1.2-jre"
    assert comps[0].source == Source.MAVEN


# ── GemCataloger ─────────────────────────────────────────────────────────────


def test_gem_gemfile_lock(tmp_path):
    content = textwrap.dedent("""\
        GEM
          remote: https://rubygems.org/
          specs:
            rails (7.0.4)
            rake (13.0.6)
            activesupport (7.0.4)
              tzinfo (~> 2.0)

        PLATFORMS
          ruby
    """)
    comps = _catalog(GemCataloger, tmp_path, {"Gemfile.lock": content})
    names = {c.name: c.version for c in comps}
    assert names["rails"] == "7.0.4"
    assert names["rake"] == "13.0.6"
    assert names["activesupport"] == "7.0.4"


def test_gem_purl(tmp_path):
    content = "GEM\n  remote: https://rubygems.org/\n  specs:\n    sinatra (3.0.6)\n"
    comps = _catalog(GemCataloger, tmp_path, {"Gemfile.lock": content})
    assert comps[0].purl == "pkg:gem/sinatra@3.0.6"
    assert comps[0].source == Source.GEM


# ── DistInfoCataloger ─────────────────────────────────────────────────────────


def test_distinfo_reads_metadata(tmp_path):
    metadata = "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\n"
    comps = _catalog(
        DistInfoCataloger,
        tmp_path,
        {"site-packages/requests-2.31.0.dist-info/METADATA": metadata},
    )
    assert len(comps) == 1
    assert comps[0].name == "requests"
    assert comps[0].version == "2.31.0"
    assert comps[0].purl == "pkg:pypi/requests@2.31.0"
    assert comps[0].source == Source.DISTINFO


def test_distinfo_skips_non_dist_info(tmp_path):
    metadata = "Metadata-Version: 2.1\nName: foo\nVersion: 1.0\n\n"
    comps = _catalog(DistInfoCataloger, tmp_path, {"src/METADATA": metadata})
    assert comps == []


# ── NodeInstalledCataloger ────────────────────────────────────────────────────


def test_node_installed_regular(tmp_path):
    pkg = {"name": "express", "version": "4.18.2"}
    comps = _catalog(
        NodeInstalledCataloger,
        tmp_path,
        {"node_modules/express/package.json": json.dumps(pkg)},
    )
    assert len(comps) == 1
    assert comps[0].name == "express"
    assert comps[0].version == "4.18.2"
    assert comps[0].purl == "pkg:npm/express@4.18.2"
    assert comps[0].source == Source.NPM


def test_node_installed_scoped(tmp_path):
    pkg = {"name": "@babel/core", "version": "7.23.0"}
    comps = _catalog(
        NodeInstalledCataloger,
        tmp_path,
        {"node_modules/@babel/core/package.json": json.dumps(pkg)},
    )
    assert len(comps) == 1
    assert comps[0].name == "@babel/core"


def test_node_installed_skips_project_root(tmp_path):
    pkg = {"name": "my-app", "version": "1.0.0"}
    comps = _catalog(NodeInstalledCataloger, tmp_path, {"package.json": json.dumps(pkg)})
    assert comps == []


# ── GemInstalledCataloger ─────────────────────────────────────────────────────


def test_gem_installed_reads_gemspec(tmp_path):
    comps = _catalog(
        GemInstalledCataloger,
        tmp_path,
        {"specifications/rails-7.0.4.gemspec": "# stub gemspec"},
    )
    assert len(comps) == 1
    assert comps[0].name == "rails"
    assert comps[0].version == "7.0.4"
    assert comps[0].purl == "pkg:gem/rails@7.0.4"
    assert comps[0].source == Source.GEM


def test_gem_installed_hyphenated_name(tmp_path):
    comps = _catalog(
        GemInstalledCataloger,
        tmp_path,
        {"specifications/activesupport-7.0.4.3.gemspec": ""},
    )
    assert comps[0].name == "activesupport"
    assert comps[0].version == "7.0.4.3"


def test_gem_installed_skips_non_specifications(tmp_path):
    comps = _catalog(
        GemInstalledCataloger,
        tmp_path,
        {"gems/rails-7.0.4/rails-7.0.4.gemspec": ""},
    )
    assert comps == []


# ── JarCataloger ─────────────────────────────────────────────────────────────


def _make_jar(path: Path, pom_props: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(path), "w") as zf:
        zf.writestr(
            "META-INF/maven/org.springframework/spring-core/pom.properties",
            pom_props,
        )


def test_jar_reads_pom_properties(tmp_path):
    props = "groupId=org.springframework\nartifactId=spring-core\nversion=5.3.20\n"
    _make_jar(tmp_path / "lib/spring-core-5.3.20.jar", props)
    cat = JarCataloger(paths=[str(tmp_path)])
    report = ScanReport()
    comps = cat.catalog(report)
    assert len(comps) == 1
    assert comps[0].name == "org.springframework/spring-core"
    assert comps[0].version == "5.3.20"
    assert comps[0].purl == "pkg:maven/org.springframework/spring-core@5.3.20"
    assert comps[0].source == Source.MAVEN


def test_jar_skips_bad_zip(tmp_path):
    bad = tmp_path / "bad.jar"
    bad.write_bytes(b"not a zip file")
    cat = JarCataloger(paths=[str(tmp_path)])
    comps = cat.catalog(ScanReport())
    assert comps == []


# ── Group expansion ───────────────────────────────────────────────────────────


def test_expand_software_group():
    result = expand_catalogers(["software"])
    assert set(result) == {"dpkg", "rpm", "apk", "registry"}


def test_expand_binary_group():
    result = expand_catalogers(["binary"])
    assert set(result) == {"binary", "win_binary"}


def test_expand_ecosystem_group():
    # "ecosystem" is a sentinel resolved by scan() — it stays as-is after expansion.
    result = expand_catalogers(["ecosystem"])
    assert result == ["ecosystem"]


def test_expand_ecosystem_project_group():
    result = expand_catalogers(["ecosystem-project"])
    assert set(result) >= {"pip", "go", "npm", "nuget", "maven", "gem"}


def test_expand_ecosystem_installed_group():
    result = expand_catalogers(["ecosystem-installed"])
    assert set(result) >= {"distinfo", "node_installed", "jar", "gem_installed"}


def test_expand_all_group():
    result = expand_catalogers(["all"])
    assert "dpkg" in result
    assert "gobinary" in result
    assert "ecosystem" in result  # sentinel present


def test_expand_individual_passthrough():
    assert expand_catalogers(["dpkg", "pip"]) == ["dpkg", "pip"]


def test_expand_deduplicates():
    result = expand_catalogers(["binary", "win_binary"])
    assert result.count("win_binary") == 1


def test_expand_mixed_group_and_individual():
    result = expand_catalogers(["software", "pip"])
    assert "dpkg" in result
    assert "pip" in result
