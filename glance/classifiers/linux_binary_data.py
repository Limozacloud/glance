"""Built-in Linux/macOS binary classifier data.

Same structure as win_registry_data.py / win_binary_data.py — a plain list of
dicts.  The loader (linux_binary.py) turns these into Classifier objects via
classifiers_from_dicts().

Each entry supports:
  class            - classifier identifier
  file_globs       - list of fnmatch-style path globs (gate)
  version_patterns - list of byte-regex strings (OR); named group "version" required
  branches         - list of sub-classifier dicts (first match wins)
  package          - canonical package name
  purl_template    - pkg:…@{version}
  cpe_templates    - list of CPE 2.3 strings with {version} placeholder
"""

from __future__ import annotations

LINUX_BINARY_CLASSIFIERS: list[dict] = [
    {
        "class": "python-binary",
        "file_globs": ["**/python*", "**/libpython*.so*"],
        "version_patterns": [
            r"(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+[-._a-zA-Z0-9]*)\x00",
        ],
        "package": "python",
        "purl_template": "pkg:generic/python@{version}",
        "cpe_templates": [
            "cpe:2.3:a:python_software_foundation:python:{version}:*:*:*:*:*:*:*",
            "cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*",
        ],
    },
    {
        "class": "python-binary-lib",
        "file_globs": ["**/libpython*.so*"],
        "version_patterns": [
            r"(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+[-._a-zA-Z0-9]*)\x00",
        ],
        "package": "python",
        "purl_template": "pkg:generic/python@{version}",
        "cpe_templates": [
            "cpe:2.3:a:python_software_foundation:python:{version}:*:*:*:*:*:*:*",
            "cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*",
        ],
    },
    {
        "class": "pypy-binary-lib",
        "file_globs": ["**/libpypy*.so*"],
        "version_patterns": [
            r"(?m)\[PyPy (?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "pypy",
        "purl_template": "pkg:generic/pypy@{version}",
        "cpe_templates": [],
    },
    {
        "class": "go-binary",
        "file_globs": ["**/go", "**/go.exe"],
        "version_patterns": [
            r"(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)\x00",
        ],
        "package": "go",
        "purl_template": "pkg:generic/go@{version}",
        "cpe_templates": ["cpe:2.3:a:golang:go:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "julia-binary",
        "file_globs": ["**/libjulia-internal.so", "**/julia"],
        "version_patterns": [
            r"\x00__init__\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00(branch|verify_methods)",
            r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00branch\x00",
            r"\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00julia version",
        ],
        "package": "julia",
        "purl_template": "pkg:generic/julia@{version}",
        "cpe_templates": ["cpe:2.3:a:julialang:julia:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "helm",
        "file_globs": ["**/helm"],
        "version_patterns": [
            r"\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]|-beta\.[0-9]|-rc\.[0-9])?)\x00{2,}",
            r"\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]|-beta\.[0-9]|-rc\.[0-9])?)\x00",
            r"@v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]|-beta\.[0-9]|-rc\.[0-9])?)\x00",
        ],
        "package": "helm",
        "purl_template": "pkg:golang/helm.sh/helm@{version}",
        "cpe_templates": ["cpe:2.3:a:helm:helm:{version}:*:*:*:*:*:*"],
    },
    {
        "class": "redis-binary",
        "file_globs": ["**/redis-server"],
        "version_patterns": [
            r"[^\d](?P<version>[0-9]+\.[0-9]+\.[0-9]+)buildkitsandbox-\d+",
            r"[^\d](?P<version>[0-9]+\.[0-9]+\.[0-9]+)\w{12}-\d+",
            r"Redis version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "redis",
        "purl_template": "pkg:generic/redis@{version}",
        "cpe_templates": [
            "cpe:2.3:a:redislabs:redis:{version}:*:*:*:*:*:*:*",
            "cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*",
        ],
    },
    {
        "class": "valkey-binary",
        "file_globs": ["**/valkey-server"],
        "version_patterns": [
            r"[^\d](?P<version>[0-9]+\.[0-9]+\.[0-9]+)buildkitsandbox-\d+",
        ],
        "package": "valkey",
        "purl_template": "pkg:generic/valkey@{version}",
        "cpe_templates": [
            "cpe:2.3:a:lfprojects:valkey:{version}:*:*:*:*:*:*:*",
            "cpe:2.3:a:linuxfoundation:valkey:{version}:*:*:*:*:*:*:*",
        ],
    },
    {
        "class": "nodejs-binary",
        "file_globs": ["**/node"],
        "version_patterns": [
            r"(?m)\x00(node )?v(?P<version>(0|4|5|6)\.[0-9]+\.[0-9]+)\x00",
            r"(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "node",
        "purl_template": "pkg:generic/node@{version}",
        "cpe_templates": ["cpe:2.3:a:nodejs:node.js:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "busybox-binary",
        "file_globs": ["**/busybox"],
        "version_patterns": [
            r"(?m)BusyBox\s+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "busybox",
        "purl_template": "pkg:generic/busybox@{version}",
        "cpe_templates": ["cpe:2.3:a:busybox:busybox:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "util-linux-binary",
        "file_globs": ["**/getopt"],
        "version_patterns": [
            r"\x00util-linux\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00",
        ],
        "package": "util-linux",
        "purl_template": "pkg:generic/util-linux@{version}",
        "cpe_templates": ["cpe:2.3:a:kernel:util-linux:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "haproxy-binary",
        "file_globs": ["**/haproxy"],
        "version_patterns": [
            r"(?m)version (?P<version>[0-9]+\.[0-9]+(\.|-dev|-rc)[0-9]+)(-[a-z0-9]{7})?, released 20",
            r"(?m)HA-Proxy version (?P<version>[0-9]+\.[0-9]+(\.|-dev)[0-9]+)",
        ],
        "package": "haproxy",
        "purl_template": "pkg:generic/haproxy@{version}",
        "cpe_templates": ["cpe:2.3:a:haproxy:haproxy:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "perl-binary",
        "file_globs": ["**/perl"],
        "version_patterns": [
            r"(?m)\/usr\/local\/lib\/perl\d\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "perl",
        "purl_template": "pkg:generic/perl@{version}",
        "cpe_templates": ["cpe:2.3:a:perl:perl:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "php-composer-binary",
        "file_globs": ["**/composer*"],
        "version_patterns": [
            r"(?m)'pretty_version'\s*=>\s*'(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)'",
        ],
        "package": "composer",
        "purl_template": "pkg:generic/composer@{version}",
        "cpe_templates": ["cpe:2.3:a:getcomposer:composer:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "httpd-binary",
        "file_globs": ["**/httpd"],
        "version_patterns": [
            r"(?m)Apache\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "httpd",
        "purl_template": "pkg:generic/httpd@{version}",
        "cpe_templates": ["cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "memcached-binary",
        "file_globs": ["**/memcached"],
        "version_patterns": [
            r"(?m)memcached\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "memcached",
        "purl_template": "pkg:generic/memcached@{version}",
        "cpe_templates": ["cpe:2.3:a:memcached:memcached:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "traefik-binary",
        "file_globs": ["**/traefik"],
        "version_patterns": [
            r"(?m)(\x00v?|\xef\xbf\xbd.?)(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00",
        ],
        "package": "traefik",
        "purl_template": "pkg:generic/traefik@{version}",
        "cpe_templates": ["cpe:2.3:a:traefik:traefik:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "arangodb-binary",
        "file_globs": ["**/arangosh"],
        "version_patterns": [
            r"(?m)\x00*(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?)\s(enterprise\s)?\[linux\]",
        ],
        "package": "arangodb",
        "purl_template": "pkg:generic/arangodb@{version}",
        "cpe_templates": ["cpe:2.3:a:arangodb:arangodb:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "postgresql-binary",
        "file_globs": ["**/postgres"],
        "version_patterns": [
            r"(?m)(\x00|\?)PostgreSQL (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)",
        ],
        "package": "postgresql",
        "purl_template": "pkg:generic/postgresql@{version}",
        "cpe_templates": ["cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "mysql-binary",
        "file_globs": ["**/mysql"],
        "version_patterns": [
            r"\x00(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)\x00+mysql",
            r"(?m).*/mysql-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)",
        ],
        "package": "mysql",
        "purl_template": "pkg:generic/mysql@{version}",
        "cpe_templates": ["cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "percona-server-binary",
        "file_globs": ["**/mysql"],
        "version_patterns": [
            r"(?m).*/percona-server-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)",
        ],
        "package": "percona-server",
        "purl_template": "pkg:generic/percona-server@{version}",
        "cpe_templates": [
            "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
            "cpe:2.3:a:percona:percona_server:{version}:*:*:*:*:*:*:*",
        ],
    },
    {
        # standalone: identifies the MySQL Server version embedded in a cluster mysqld
        "class": "mysqld-mysql-cluster-legacy-binary",
        "file_globs": ["**/mysqld"],
        "version_patterns": [
            r"cluster-gpl\x00(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?)\-ndb\-[0-9]+(\.[0-9]+)?(\.[0-9]+)?",
        ],
        "package": "mysql-server",
        "purl_template": "pkg:generic/mysql-server@{version}",
        "cpe_templates": [
            "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
            "cpe:2.3:a:oracle:mysql_server:{version}:*:*:*:*:*:*:*",
        ],
    },
    {
        "class": "mysqld-binary",
        "file_globs": ["**/mysqld"],
        "branches": [
            {
                "class": "mysqld-mysql-cluster-legacy-binary",
                "version_patterns": [
                    r"cluster-gpl\x00[0-9]+(\.[0-9]+)?(\.[0-9]+)?\-ndb\-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?)",
                ],
                "package": "mysql-cluster",
                "purl_template": "pkg:generic/mysql-cluster@{version}",
                "cpe_templates": ["cpe:2.3:a:oracle:mysql_cluster:{version}:*:*:*:*:*:*:*"],
            },
            {
                "class": "mysqld-mysql-cluster-binary",
                "version_patterns": [
                    r"/mysql-cluster-gpl-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)/",
                ],
                "package": "mysql-cluster",
                "purl_template": "pkg:generic/mysql-cluster@{version}",
                "cpe_templates": [
                    "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
                    "cpe:2.3:a:oracle:mysql_cluster:{version}:*:*:*:*:*:*:*",
                ],
            },
            {
                "class": "mysqld-mysql-server-binary",
                "version_patterns": [
                    r"/mysql-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)/",
                ],
                "package": "mysql-server",
                "purl_template": "pkg:generic/mysql-server@{version}",
                "cpe_templates": [
                    "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
                    "cpe:2.3:a:oracle:mysql_server:{version}:*:*:*:*:*:*:*",
                ],
            },
        ],
    },
    {
        "class": "mysql-cluster-ndbd",
        "file_globs": ["**/ndbd", "**/ndbmtd", "**/ndb_mgmd"],
        "version_patterns": [
            r"/mysql-cluster-gpl-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)/",
        ],
        "package": "mysql-cluster",
        "purl_template": "pkg:generic/mysql-cluster@{version}",
        "cpe_templates": ["cpe:2.3:a:oracle:mysql_cluster:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "xtrabackup-binary",
        "file_globs": ["**/xtrabackup"],
        "version_patterns": [
            r"(?m).*/percona-xtrabackup-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)",
        ],
        "package": "percona-xtrabackup",
        "purl_template": "pkg:generic/percona-xtrabackup@{version}",
        "cpe_templates": ["cpe:2.3:a:percona:xtrabackup:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "mariadb-binary",
        "file_globs": ["**/mariadb", "**/mysql"],
        "version_patterns": [
            r"(?m)(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)-MariaDB",
            r"(?m)(?:^|/)mariadb-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)-",
        ],
        "package": "mariadb",
        "purl_template": "pkg:generic/mariadb@{version}",
        "cpe_templates": ["cpe:2.3:a:mariadb:mariadb:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "rust-standard-library-linux",
        "file_globs": ["**/libstd-????????????????.so"],
        "version_patterns": [
            r"(?m)(\x00)clang LLVM \(rustc version (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)",
        ],
        "package": "rust",
        "purl_template": "pkg:generic/rust@{version}",
        "cpe_templates": ["cpe:2.3:a:rust-lang:rust:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "rust-standard-library-macos",
        "file_globs": ["**/libstd-????????????????.dylib"],
        "version_patterns": [
            r"(?m)c (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)",
        ],
        "package": "rust",
        "purl_template": "pkg:generic/rust@{version}",
        "cpe_templates": ["cpe:2.3:a:rust-lang:rust:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "ruby-binary",
        "file_globs": ["**/ruby", "**/libruby.so*"],
        "version_patterns": [
            r"(?m)ruby (?P<version>[0-9]+\.[0-9]+\.[0-9]+((p|preview|rc|dev)[0-9]*)?) ",
        ],
        "package": "ruby",
        "purl_template": "pkg:generic/ruby@{version}",
        "cpe_templates": ["cpe:2.3:a:ruby-lang:ruby:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "erlang-binary",
        "file_globs": ["**/erlexec", "**/beam.smp", "**/liberts_internal.a"],
        "version_patterns": [
            r"(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/",
            r"(?m)/usr/local/src/otp-(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/",
            r"\x00+(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)\x00+Erlang/OTP",
        ],
        "package": "erlang",
        "purl_template": "pkg:generic/erlang@{version}",
        "cpe_templates": ["cpe:2.3:a:erlang:erlang\\/otp:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "swipl-binary",
        "file_globs": ["**/swipl"],
        "version_patterns": [
            r"(?m)swipl-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\/",
        ],
        "package": "swipl",
        "purl_template": "pkg:generic/swipl@{version}",
        "cpe_templates": ["cpe:2.3:a:swi-prolog:swi-prolog:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "dart-binary",
        "file_globs": ["**/dart"],
        "version_patterns": [
            r"(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+(\.[0-9]+)?\.beta)?) ",
        ],
        "package": "dart",
        "purl_template": "pkg:generic/dart@{version}",
        "cpe_templates": ["cpe:2.3:a:dart:dart_software_development_kit:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "deno-binary",
        "file_globs": ["**/deno"],
        "version_patterns": [
            r"Deno/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
            r"deno-[0-9a-z]{40}release/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
            r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)[0-9a-z]{40}DENO",
        ],
        "package": "deno",
        "purl_template": "pkg:generic/deno@{version}",
        "cpe_templates": ["cpe:2.3:a:deno:deno:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "haskell-ghc-binary",
        "file_globs": ["**/ghc*"],
        "version_patterns": [
            r"(?m)\x00GHC (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00",
            r"\x00libHSghc\-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\-([a-zA-Z0-9]+\-)?ghc[0-9]+\.[0-9]+\.[0-9]+\.so\x00",
        ],
        "package": "haskell/ghc",
        "purl_template": "pkg:generic/haskell/ghc@{version}",
        "cpe_templates": ["cpe:2.3:a:haskell:ghc:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "haskell-cabal-binary",
        "file_globs": ["**/cabal"],
        "version_patterns": [
            r"(?m)\x00Cabal-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)-",
        ],
        "package": "haskell/cabal",
        "purl_template": "pkg:generic/haskell/cabal@{version}",
        "cpe_templates": ["cpe:2.3:a:haskell:cabal:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "haskell-stack-binary",
        "file_globs": ["**/stack"],
        "version_patterns": [
            r"(?m)Version\s*(?P<version>[0-9]+\.[0-9]+\.[0-9]+),\s*Git",
        ],
        "package": "haskell/stack",
        "purl_template": "pkg:generic/haskell/stack@{version}",
        "cpe_templates": ["cpe:2.3:a:haskell:stack:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "consul-binary",
        "file_globs": ["**/consul"],
        "version_patterns": [
            r"CONSUL_VERSION: (?P<version>\d+\.\d+\.\d+)",
            r'GitDescribe=(?P<version>\d+\.\d+\.\d+)"',
            r"\x00+v(?P<version>\d+\.\d+\.\d+)\x00+",
        ],
        "package": "consul",
        "purl_template": "pkg:golang/github.com/hashicorp/consul@{version}",
        "cpe_templates": ["cpe:2.3:a:hashicorp:consul:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "hashicorp-vault-binary",
        "file_globs": ["**/vault"],
        "version_patterns": [
            r"(?m)revoke(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
            r"state(?P<version>[0-9]+\.[0-9]+\.[0-9]+\-rc[0-9])",
            r"\x00+(?P<version>1\.[0-9][0,1]?\.[0-9]+)\x00+",
        ],
        "package": "github.com/hashicorp/vault",
        "purl_template": "pkg:golang/github.com/hashicorp/vault@{version}",
        "cpe_templates": ["cpe:2.3:a:hashicorp:vault:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "nginx-binary",
        "file_globs": ["**/nginx"],
        "version_patterns": [
            r"(?m)(\x00|\?)nginx version: [^\/]+\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:\+\d+)?(?:-\d+)?)",
        ],
        "package": "nginx",
        "purl_template": "pkg:generic/nginx@{version}",
        "cpe_templates": [
            "cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*",
            "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
        ],
    },
    {
        "class": "bash-binary",
        "file_globs": ["**/bash"],
        "version_patterns": [
            r"(?m)@\(#\)Bash version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\([0-9]\) [a-z0-9]+ GNU",
        ],
        "package": "bash",
        "purl_template": "pkg:generic/bash@{version}",
        "cpe_templates": ["cpe:2.3:a:gnu:bash:{version}:*:*:*:*:*:*:*"],
    },
    {
        # glance: also gates libcrypto/libssl — the version string lives there too,
        # which is exactly the unmanaged/vendored copy OSV/Trivy miss.
        "class": "openssl-binary",
        "file_globs": ["**/openssl", "**/libcrypto.so*", "**/libssl.so*"],
        "branches": [
            {
                "class": "openssl-binary-aws-lc",
                "version_patterns": [
                    r"AWS-LC (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\)\x00",
                ],
                "package": "aws-lc",
                "purl_template": "pkg:generic/aws-lc@{version}",
                "cpe_templates": ["cpe:2.3:a:amazon:aws_libcrypto:{version}:*:*:*:*:*:*:*"],
            },
            {
                "class": "openssl-binary",
                "version_patterns": [
                    r"\x00OpenSSL (?P<version>[0-9]+\.[0-9]+\.[0-9]+([a-z]+|-alpha[0-9]|-beta[0-9]|-rc[0-9])?)",
                ],
                "package": "openssl",
                "purl_template": "pkg:generic/openssl@{version}",
                "cpe_templates": ["cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*"],
            },
        ],
    },
    {
        "class": "openldap-search-binary",
        "file_globs": ["**/ldapsearch"],
        "version_patterns": [
            r"\$OpenLDAP:\sldapsearch\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "openldap",
        "purl_template": "pkg:generic/openldap@{version}",
        "cpe_templates": ["cpe:2.3:a:openldap:openldap:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "qt-qtbase-lib",
        "file_globs": ["**/libQt*Core.so*"],
        "version_patterns": [
            r"\x00\x00Qt (?P<version>[0-9]+\.[0-9]+\.[0-9]+) \(",
            r"QtCore library version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "qtbase",
        "purl_template": "pkg:generic/qtbase@{version}",
        "cpe_templates": [
            "cpe:2.3:a:qt:qt:{version}:*:*:*:*:*:*:*",
            "cpe:2.3:a:qt:qtbase:{version}:*:*:*:*:*:*:*",
        ],
    },
    {
        "class": "gcc-binary",
        "file_globs": ["**/gcc"],
        "version_patterns": [
            r"GCC: \(GNU\) (?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "gcc",
        "purl_template": "pkg:generic/gcc@{version}",
        "cpe_templates": ["cpe:2.3:a:gnu:gcc:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "fluent-bit-binary",
        "file_globs": ["**/fluent-bit"],
        "version_patterns": [
            r"\x00(\x00)?(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00(\x1b\[1m\x00|\x00|\x00\x00)?(%s)?Fluent",
        ],
        "package": "fluent-bit",
        "purl_template": "pkg:github/fluent/fluent-bit@{version}",
        "cpe_templates": ["cpe:2.3:a:treasuredata:fluent_bit:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "wordpress-cli-binary",
        "file_globs": ["**/wp"],
        "version_patterns": [
            r"(?m)wp-cli/wp-cli (?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "wp-cli",
        "purl_template": "pkg:generic/wp-cli@{version}",
        "cpe_templates": ["cpe:2.3:a:wp-cli:wp-cli:{version}:*:*:*:*:*:*:*"],
    },
    {
        # glance: also gates libcurl.so — its UA string "libcurl/8.5.0" matches.
        "class": "curl-binary",
        "file_globs": ["**/curl", "**/libcurl.so*"],
        "version_patterns": [
            r"curl/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "curl",
        "purl_template": "pkg:generic/curl@{version}",
        "cpe_templates": ["cpe:2.3:a:haxx:curl:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "lighttpd-binary",
        "file_globs": ["**/lighttpd"],
        "version_patterns": [
            r"\x00lighttpd/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00",
        ],
        "package": "lighttpd",
        "purl_template": "pkg:generic/lighttpd@{version}",
        "cpe_templates": ["cpe:2.3:a:lighttpd:lighttpd:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "proftpd-binary",
        "file_globs": ["**/proftpd"],
        "version_patterns": [
            r"\x00ProFTPD Version (?P<version>[0-9]+\.[0-9]+\.[0-9]+[a-z]?)\x00",
        ],
        "package": "proftpd",
        "purl_template": "pkg:generic/proftpd@{version}",
        "cpe_templates": ["cpe:2.3:a:proftpd:proftpd:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "zstd-binary",
        "file_globs": ["**/zstd"],
        "version_patterns": [
            r"\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00",
        ],
        "package": "zstd",
        "purl_template": "pkg:generic/zstd@{version}",
        "cpe_templates": ["cpe:2.3:a:facebook:zstandard:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "xz-binary",
        "file_globs": ["**/xz"],
        "version_patterns": [
            r"\x00xz \(XZ Utils\) (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00",
        ],
        "package": "xz",
        "purl_template": "pkg:generic/xz@{version}",
        "cpe_templates": ["cpe:2.3:a:tukaani:xz:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "gzip-binary",
        "file_globs": ["**/gzip"],
        "version_patterns": [
            r"\x00(?P<version>[0-9]+\.[0-9]+)\x00",
        ],
        "package": "gzip",
        "purl_template": "pkg:generic/gzip@{version}",
        "cpe_templates": ["cpe:2.3:a:gnu:gzip:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "sqlcipher-binary",
        "file_globs": ["**/sqlcipher"],
        "version_patterns": [
            r"[^0-9]\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00",
        ],
        "package": "sqlcipher",
        "purl_template": "pkg:generic/sqlcipher@{version}",
        "cpe_templates": ["cpe:2.3:a:zetetic:sqlcipher:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "jq-binary",
        "file_globs": ["**/jq"],
        "version_patterns": [
            r"\x00(?P<version>[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]+)?)\x00",
        ],
        "package": "jq",
        "purl_template": "pkg:generic/jq@{version}",
        "cpe_templates": ["cpe:2.3:a:jqlang:jq:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "chrome-binary",
        "file_globs": ["**/chrome"],
        "version_patterns": [
            r"\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\x00Default",
        ],
        "package": "chrome",
        "purl_template": "pkg:generic/chrome@{version}",
        "cpe_templates": ["cpe:2.3:a:google:chrome:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "ffmpeg-binary",
        "file_globs": ["**/ffmpeg", "**/libav*", "**/libswresample*"],
        "version_patterns": [
            r"(?m)%s version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)",
            r"(?m)FFmpeg version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)",
            r"(?m)Lavc(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "ffmpeg",
        "purl_template": "pkg:generic/ffmpeg@{version}",
        "cpe_templates": ["cpe:2.3:a:ffmpeg:ffmpeg:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "elixir-binary",
        "file_globs": ["**/elixir", "**/elixir/ebin/elixir.app"],
        "version_patterns": [
            r"(?m)ELIXIR_VERSION=(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:\.[0-9]+)?)?)",
            r'(?m)\{vsn,"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:\.[0-9]+)?)?)"\}',
        ],
        "package": "elixir",
        "purl_template": "pkg:generic/elixir@{version}",
        "cpe_templates": ["cpe:2.3:a:elixir-lang:elixir:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "istio-binary",
        "file_globs": ["**/pilot-discovery", "**/pilot-agent"],
        "version_patterns": [
            r"Clean\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+",
            r"Modified\x00+(?P<version>[0-9]+\.[0-9]+-dev)\x00+",
            r"[0-9]+\.[0-9]+\.[0-9]+\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+",
        ],
        "package": "istio",
        "purl_template": "pkg:generic/istio@{version}",
        "cpe_templates": ["cpe:2.3:a:istio:istio:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "grafana-binary",
        "file_globs": ["**/grafana", "**/grafana-server"],
        "version_patterns": [
            r"\x00+release-(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+",
            r"(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+\$a",
            r"HEAD\x00+.*\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+",
        ],
        "package": "grafana",
        "purl_template": "pkg:generic/grafana@{version}",
        "cpe_templates": ["cpe:2.3:a:grafana:grafana:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "envoy-binary",
        "file_globs": ["**/envoy"],
        "version_patterns": [
            r"(?s)\x00(?P<version>1\.3[0-9]\.[0-9]+(-dev)?)\x00.{0,1000}envoy_reloadable_features",
            r"(?s)envoy_quic_.{0,1000}\x00(?P<version>1\.2[0-9]\.[0-9]+(-dev)?)\x00",
            r"(?s)\x00(?P<version>1\.[12][0-9]\.[0-9]+(-dev)?)\x00.{0,1000}Unable to",
        ],
        "package": "envoy",
        "purl_template": "pkg:generic/envoy@{version}",
        "cpe_templates": ["cpe:2.3:a:envoyproxy:envoy:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "mongodb-binary",
        "file_globs": ["**/mongod"],
        "version_patterns": [
            r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00tcmalloc",
            r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+heap_size",
            r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+cppdefines",
        ],
        "package": "mongodb",
        "purl_template": "pkg:generic/mongodb@{version}",
        "cpe_templates": ["cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "ingress-nginx-binary",
        "file_globs": ["**/nginx-ingress-controller"],
        "version_patterns": [
            r"v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+.{0,50}go[0-9]+\.[0-9]+(\-(alpha|beta)\.[0-9])?\.[0-9]+\x00+",
            r"\x00+go[0-9]+\.[0-9]+\.[0-9]+\x00+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\-(alpha|beta)\.[0-9])?)\x00+",
            r"\x00+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+\-(alpha|beta)\.[0-9])\x00+",
        ],
        "package": "nginx-ingress-controller",
        "purl_template": "pkg:generic/nginx-ingress-controller@{version}",
        "cpe_templates": ["cpe:2.3:a:kubernetes:ingress-nginx:{version}:*:*:*:*:*:*:*"],
    },
    {
        "class": "elastic-agent-binary",
        "file_globs": ["**/elastic-agent"],
        "version_patterns": [
            r"enroll(?:: true)?(?P<version>[0-9]+\.[0-9]+\.[0-9]+)-?header",
            r"PM(?P<version>[0-9]+\.[0-9]+\.[0-9]+):https",
        ],
        "package": "elastic-agent",
        "purl_template": "pkg:generic/elastic-agent@{version}",
        "cpe_templates": ["cpe:2.3:a:elastic:elastic_agent:{version}:*:*:*:*:*:*:*"],
    },
    # ---- Java/JVM ---------------------------------------------------------------
    {
        "class": "java-binary",
        "file_globs": ["**/java", "**/jdb"],
        "branches": [
            {
                "class": "java-binary-graalvm",
                "version_patterns": [
                    r"(?m)\x00(?P<version>[0-9]+[.0-9]+[.0-9]+\+[0-9]+-jvmci-[0-9]+[.0-9]+-b[0-9]+)\x00",
                ],
                "package": "graalvm",
                "purl_template": "pkg:generic/oracle/graalvm@{version}",
                "cpe_templates": ["cpe:2.3:a:oracle:graalvm:{version}:*:*:*:*:*:*:*"],
            },
            {
                "class": "java-binary-openjdk-with-update",
                "version_patterns": [
                    r"(?m)java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>(?P<primary>[0-9]+[^\x00]+)_(?P<update>[^\x00]+)-[^\x00]+)\x00",
                ],
                "package": "openjdk",
                "purl_template": "pkg:generic/oracle/openjdk@{version}",
                "cpe_templates": [
                    "cpe:2.3:a:oracle:openjdk:{version}:update{{.update}}:*:*:*:*:*:*",
                ],
            },
            {
                "class": "java-binary-openjdk",
                "version_patterns": [
                    r"(?m)\x00openjdk\x00java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00",
                    r"(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>[0-9]+[^\x00]+)\x00+openjdk\x00java",
                ],
                "package": "openjdk",
                "purl_template": "pkg:generic/oracle/openjdk@{version}",
                "cpe_templates": ["cpe:2.3:a:oracle:openjdk:{version}:*:*:*:*:*:*:*"],
            },
            {
                "class": "java-binary-oracle",
                "version_patterns": [
                    r"(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[-._+a-zA-Z0-9]+)\x00",
                ],
                "package": "jre",
                "purl_template": "pkg:generic/oracle/jre@{version}",
                "cpe_templates": ["cpe:2.3:a:oracle:jre:{version}:*:*:*:*:*:*:*"],
            },
        ],
    },
    # ---- glance additions (CVE-gap driven; validated against real .so) ----------
    {
        # TIFFGetVersion() string, confirmed on libtiff.so.6.0.1
        "class": "libtiff-library",
        "file_globs": ["**/libtiff.so*"],
        "version_patterns": [
            r"LIBTIFF, Version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "libtiff",
        "purl_template": "pkg:generic/libtiff@{version}",
        "cpe_templates": ["cpe:2.3:a:libtiff:libtiff:{version}:*:*:*:*:*:*:*"],
    },
    {
        # XML_ExpatVersion(), confirmed on libexpat.so.1: "expat_2.6.1"
        "class": "expat-library",
        "file_globs": ["**/libexpat.so*"],
        "version_patterns": [
            r"expat_(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "expat",
        "purl_template": "pkg:generic/expat@{version}",
        "cpe_templates": ["cpe:2.3:a:libexpat_project:libexpat:{version}:*:*:*:*:*:*:*"],
    },
    {
        # pcre2: "10.42 2022-12-11" — build date disambiguates from Unicode version
        "class": "pcre2-library",
        "file_globs": ["**/libpcre2-8.so*", "**/libpcre2-16.so*", "**/libpcre2-32.so*"],
        "version_patterns": [
            r"(?P<version>[0-9]+\.[0-9]+) [0-9]{4}-[0-9]{2}-[0-9]{2}",
        ],
        "package": "pcre2",
        "purl_template": "pkg:generic/pcre2@{version}",
        "cpe_templates": ["cpe:2.3:a:pcre:pcre2:{version}:*:*:*:*:*:*:*"],
    },
    {
        # SSH-2.0-libssh_0.10.6, confirmed on libssh.so.4
        "class": "libssh-library",
        "file_globs": ["**/libssh.so*"],
        "version_patterns": [
            r"libssh_(?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "libssh",
        "purl_template": "pkg:generic/libssh@{version}",
        "cpe_templates": ["cpe:2.3:a:libssh:libssh:{version}:*:*:*:*:*:*:*"],
    },
    {
        # png_get_copyright(), confirmed on libpng16.so.16: "libpng version 1.6.43"
        "class": "libpng-library",
        "file_globs": ["**/libpng*.so*"],
        "version_patterns": [
            r"libpng version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "libpng",
        "purl_template": "pkg:generic/libpng@{version}",
        "cpe_templates": ["cpe:2.3:a:libpng:libpng:{version}:*:*:*:*:*:*:*"],
    },
    {
        # archive_version_string(), confirmed on libarchive.so.13: "libarchive 3.7.2"
        "class": "libarchive-library",
        "file_globs": ["**/libarchive.so*"],
        "version_patterns": [
            r"libarchive (?P<version>[0-9]+\.[0-9]+\.[0-9]+)",
        ],
        "package": "libarchive",
        "purl_template": "pkg:generic/libarchive@{version}",
        "cpe_templates": ["cpe:2.3:a:libarchive:libarchive:{version}:*:*:*:*:*:*:*"],
    },
]
