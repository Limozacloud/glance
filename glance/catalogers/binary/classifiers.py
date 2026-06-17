"""Faithful data port of Syft's binary-cataloger classifiers.

Each classifier is a file-glob gate plus an evidence matcher, mirroring the
``DefaultClassifiers`` / ``defaultJavaClassifiers`` tables from Anchore Syft's
``pkg/cataloger/binary`` package. Order is significant (it drives precedence),
so entries appear in the same sequence as the Go source.

PURLs use ``@{version}`` placeholders and CPEs carry ``{version}`` in the
version field; both are rendered once a concrete version is extracted.
"""

from __future__ import annotations

from .matchers import (
    Classifier,
    all_of,
    any_of,
    branching,
    contents,
    filename_template,
    none_of,
    path_glob,
    shared_library,
    supporting,
)

# --------------------------------------------------------------------------- #
# shared matchers (mirror the package-level vars at the top of classifiers.go)
# --------------------------------------------------------------------------- #
# in both binaries and shared libraries, the version pattern is [NUL]3.11.2[NUL]
python_version_template = rb"(?m)\x00(?P<version>{{ .version }}[-._a-zA-Z0-9]*)\x00"

libpython_matcher = filename_template(
    r"(?:.*/|^)libpython(?P<version>[0-9]+(?:\.[0-9]+)+)[a-z]?\.so.*$",
    python_version_template,
)

# ruby 3.4.0dev (2024-09-15T01:06:11Z master 532af89e3b) [x86_64-linux]
# ruby 2.7.7p221 (2022-11-24 revision 168ec2b1e5) [x86_64-linux]
ruby_matcher = contents(
    rb"(?m)ruby (?P<version>[0-9]+\.[0-9]+\.[0-9]+((p|preview|rc|dev)[0-9]*)?) "
)


def default_classifiers() -> list[Classifier]:
    """Return all binary classifiers (binary table + java table), in order."""
    classifiers: list[Classifier] = [
        Classifier(
            cls="python-binary",
            file_globs=["**/python*"],
            matcher=any_of(
                # try to find version information from libpython shared libraries
                shared_library(
                    r"^libpython[0-9]+(?:\.[0-9]+)+[a-z]?\.so.*$",
                    libpython_matcher,
                ),
                # check for version information in the binary
                filename_template(
                    r"(?:.*/|^)python(?P<version>[0-9]+(?:\.[0-9]+)+)$",
                    python_version_template,
                ),
            ),
            package="python",
            purl_template="pkg:generic/python@{version}",
            cpe_templates=[
                "cpe:2.3:a:python_software_foundation:python:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*",
            ],
        ),
        Classifier(
            cls="python-binary-lib",
            file_globs=["**/libpython*.so*"],
            matcher=libpython_matcher,
            package="python",
            purl_template="pkg:generic/python@{version}",
            cpe_templates=[
                "cpe:2.3:a:python_software_foundation:python:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*",
            ],
        ),
        Classifier(
            cls="pypy-binary-lib",
            file_globs=["**/libpypy*.so*"],
            matcher=contents(rb"(?m)\[PyPy (?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            package="pypy",
            purl_template="pkg:generic/pypy@{version}",
            cpe_templates=[],
        ),
        Classifier(
            cls="go-binary",
            file_globs=["**/{go,go.exe}"],
            matcher=any_of(
                contents(
                    rb"(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)\x00"
                ),
                supporting(
                    "VERSION*",
                    contents(
                        rb"(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+|-[_0-9a-z]+)?)"
                    ),
                ),
                supporting(
                    "../VERSION*",
                    contents(
                        rb"(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+|-[_0-9a-z]+)?)"
                    ),
                ),
            ),
            package="go",
            purl_template="pkg:generic/go@{version}",
            cpe_templates=["cpe:2.3:a:golang:go:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="julia-binary",
            file_globs=["**/libjulia-internal.so"],
            matcher=any_of(
                # [NUL]GIT_VERSION_INFO[NUL]__init__[NUL]1.12.6[NUL]branch[NUL]commit
                contents(
                    rb"\x00__init__\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00(branch|verify_methods)"
                ),
                contents(
                    rb"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00branch\x00"
                ),
                # [NUL]verify_methods[NUL]Task cannot be serialized[NUL]1.9.0-alpha1[NUL]BigInt[NUL]
                contents(
                    rb"\x00verify_methods\x00.{0,30}(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00BigInt"
                ),
                # unknown option `%s`[NUL]1.8.5[NUL]julia version %s
                contents(
                    rb"\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00julia version"
                ),
            ),
            package="julia",
            purl_template="pkg:generic/julia@{version}",
            cpe_templates=["cpe:2.3:a:julialang:julia:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="julia-binary",
            file_globs=["**/julia"],
            matcher=shared_library(
                # libjulia.so.1 / libjulia.so.0.6 / libjulia.so
                r"^libjulia\.so(\.[0-9])?(\.[0-9])?$",
                any_of(
                    contents(
                        rb"\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00julia version"
                    ),
                    # [NUL]#kw#[NUL]1.3.1[NUL]BigInt
                    contents(
                        rb"\x00#kw#\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00(BigInt|_require_dependencies)"
                    ),
                    # [NUL]ObjectIdDict[NUL]0.6.4[NUL]jl_sysimg_cpu_target
                    contents(
                        rb"\x00ObjectIdDict\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00jl_sysimg_cpu_target"
                    ),
                    # [NUL]require[NUL]0.4.6[NUL]core2
                    contents(
                        rb"\x00require\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00core2"
                    ),
                ),
            ),
            package="julia",
            purl_template="pkg:generic/julia@{version}",
            cpe_templates=["cpe:2.3:a:julialang:julia:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="helm",
            file_globs=["**/helm"],
            matcher=any_of(
                # [NUL]v1.21.2[NUL].......[NUL][NUL]v4.1.4[NUL][NUL][NUL]
                contents(
                    rb"\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]|-beta\.[0-9]|-rc\.[0-9])?)\x00{2,}"
                ),
                # [NUK]'[DLE]v3.12.0[NUL][NUL]...go1.20.3[NUL][NUL]
                contents(
                    rb"v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]|-beta\.[0-9]|-rc\.[0-9])?)\x00+.{1,500}go[0-9]+\.[0-9]+\.[0-9]+\x00+"
                ),
                # [NUL]v3.11.1[NUL]?[NUL]
                contents(
                    rb"\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]|-beta\.[0-9]|-rc\.[0-9])?)\x00"
                ),
                # [NUL]@?@v3.15.2[NUL][NUL]
                contents(
                    rb"@v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]|-beta\.[0-9]|-rc\.[0-9])?)\x00"
                ),
            ),
            package="helm",
            purl_template="pkg:golang/helm.sh/helm@{version}",
            cpe_templates=["cpe:2.3:a:helm:helm:{version}:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="redis-binary",
            file_globs=["**/redis-server"],
            matcher=all_of(
                # Negative Matchers to exclude valkey-server
                none_of(path_glob("**/valkey-server")),
                any_of(
                    # "7.0.14buildkitsandbox-1702957741000000000"
                    contents(rb"[^\d](?P<version>\d+.\d+\.\d+)buildkitsandbox-\d+"),
                    # "4.0.11841ce7054bd9-1542359302000000000"
                    contents(rb"[^\d](?P<version>[0-9]+\.[0-9]+\.[0-9]+)\w{12}-\d+"),
                    # "Server started, Redis version 2.8.23"
                    contents(rb"Redis version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
                ),
            ),
            package="redis",
            purl_template="pkg:generic/redis@{version}",
            cpe_templates=[
                "cpe:2.3:a:redislabs:redis:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*",
            ],
        ),
        Classifier(
            cls="valkey-binary",
            file_globs=["**/valkey-server"],
            # valkey9.0.0buildkitsandbox-1764887574000000000
            matcher=contents(rb"[^\d](?P<version>\d+.\d+\.\d+)buildkitsandbox-\d+"),
            package="valkey",
            purl_template="pkg:generic/valkey@{version}",
            cpe_templates=[
                "cpe:2.3:a:lfprojects:valkey:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:linuxfoundation:valkey:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:valkey-io:valkey:{version}:*:*:*:*:*:*:*",
            ],
        ),
        Classifier(
            cls="nodejs-binary",
            file_globs=["**/node"],
            matcher=any_of(
                # [NUL]node v0.10.48[NUL] / [NUL]v4.9.1[NUL]
                contents(rb"(?m)\x00(node )?v(?P<version>(0|4|5|6)\.[0-9]+\.[0-9]+)\x00"),
                contents(rb"(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            ),
            package="node",
            purl_template="pkg:generic/node@{version}",
            cpe_templates=["cpe:2.3:a:nodejs:node.js:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="busybox-binary",
            file_globs=["**/busybox"],
            matcher=contents(rb"(?m)BusyBox\s+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            package="busybox",
            purl_template="pkg:generic/busybox@{version}",
            cpe_templates=["cpe:2.3:a:busybox:busybox:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="util-linux-binary",
            file_globs=["**/getopt"],
            matcher=contents(rb"\x00util-linux\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00"),
            package="util-linux",
            purl_template="pkg:generic/util-linux@{version}",
            cpe_templates=["cpe:2.3:a:kernel:util-linux:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="haproxy-binary",
            file_globs=["**/haproxy"],
            matcher=any_of(
                contents(
                    rb"(?m)version (?P<version>[0-9]+\.[0-9]+(\.|-dev|-rc)[0-9]+)(-[a-z0-9]{7})?, released 20"
                ),
                contents(rb"(?m)HA-Proxy version (?P<version>[0-9]+\.[0-9]+(\.|-dev)[0-9]+)"),
                contents(
                    rb"(?m)(?P<version>[0-9]+\.[0-9]+(\.|-dev)[0-9]+)-[0-9a-zA-Z]{7}.+HAProxy version"
                ),
            ),
            package="haproxy",
            purl_template="pkg:generic/haproxy@{version}",
            cpe_templates=["cpe:2.3:a:haproxy:haproxy:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="perl-binary",
            file_globs=["**/perl"],
            matcher=contents(
                rb"(?m)\/usr\/local\/lib\/perl\d\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"
            ),
            package="perl",
            purl_template="pkg:generic/perl@{version}",
            cpe_templates=["cpe:2.3:a:perl:perl:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="php-composer-binary",
            file_globs=["**/composer*"],
            matcher=contents(
                rb"(?m)'pretty_version'\s*=>\s*'(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)'"
            ),
            package="composer",
            purl_template="pkg:generic/composer@{version}",
            cpe_templates=["cpe:2.3:a:getcomposer:composer:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="httpd-binary",
            file_globs=["**/httpd"],
            matcher=contents(rb"(?m)Apache\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            package="httpd",
            purl_template="pkg:generic/httpd@{version}",
            cpe_templates=["cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="memcached-binary",
            file_globs=["**/memcached"],
            matcher=contents(rb"(?m)memcached\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            package="memcached",
            purl_template="pkg:generic/memcached@{version}",
            cpe_templates=["cpe:2.3:a:memcached:memcached:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="traefik-binary",
            file_globs=["**/traefik"],
            # [NUL]v1.7.34[NUL] / [NUL]2.9.6[NUL] / 3.0.4[NUL]
            # Go's \x{FFFD} (U+FFFD) -> UTF-8 bytes \xef\xbf\xbd
            matcher=contents(
                rb"(?m)(\x00v?|\xef\xbf\xbd.?)(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00"
            ),
            package="traefik",
            purl_template="pkg:generic/traefik@{version}",
            cpe_templates=["cpe:2.3:a:traefik:traefik:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="arangodb-binary",
            file_globs=["**/arangosh"],
            matcher=contents(
                rb"(?m)\x00*(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?)\s(enterprise\s)?\[linux\]"
            ),
            package="arangodb",
            purl_template="pkg:generic/arangodb@{version}",
            cpe_templates=["cpe:2.3:a:arangodb:arangodb:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="postgresql-binary",
            file_globs=["**/postgres"],
            # [NUL]PostgreSQL 15beta4 / [NUL]PostgreSQL 9.6.24 / ?PostgreSQL 9.5alpha1
            matcher=contents(
                rb"(?m)(\x00|\?)PostgreSQL (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)"
            ),
            package="postgresql",
            purl_template="pkg:generic/postgresql@{version}",
            cpe_templates=["cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="mysql-binary",
            file_globs=["**/mysql"],
            matcher=any_of(
                # shutdown[NUL]8.0.37[NUL][NUL][NUL][NUL][NUL]mysql_real_esc
                contents(
                    rb"\x00(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)\x00+mysql"
                ),
                # /.../release/mysql-8.0.4-rc/mysys_ssl/my_default.cc
                contents(
                    rb"(?m).*/mysql-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)"
                ),
            ),
            package="mysql",
            purl_template="pkg:generic/mysql@{version}",
            cpe_templates=["cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="mysql-binary",
            file_globs=["**/mysql"],
            matcher=contents(
                rb"(?m).*/percona-server-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)"
            ),
            package="percona-server",
            purl_template="pkg:generic/percona-server@{version}",
            cpe_templates=[
                "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:percona:percona_server:{version}:*:*:*:*:*:*:*",
            ],
        ),
        Classifier(
            cls="mysql-binary",
            file_globs=["**/mysql"],
            matcher=contents(
                rb"(?m).*/Percona-XtraDB-Cluster-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)"
            ),
            package="percona-xtradb-cluster",
            purl_template="pkg:generic/percona-xtradb-cluster@{version}",
            cpe_templates=[
                "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:percona:percona_server:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:percona:xtradb_cluster:{version}:*:*:*:*:*:*:*",
            ],
        ),
        Classifier(
            # Legacy MySQL Cluster: identifies the MySQL Server version (e.g. 5.7.33)
            cls="mysqld-mysql-cluster-legacy-binary",
            file_globs=["**/mysqld"],
            matcher=contents(
                rb"cluster-gpl\x00(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?)\-ndb\-[0-9]+(\.[0-9]+)?(\.[0-9]+)?"
            ),
            package="mysql-server",
            purl_template="pkg:generic/mysql-server@{version}",
            cpe_templates=[
                "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:oracle:mysql_server:{version}:*:*:*:*:*:*:*",
            ],
        ),
        Classifier(
            cls="mysqld-binary",
            file_globs=["**/mysqld"],
            matcher=branching(
                Classifier(
                    # Legacy MySQL Cluster: identifies the MySQL Cluster version (e.g. 7.5.21)
                    cls="mysqld-mysql-cluster-legacy-binary",
                    file_globs=[],
                    matcher=contents(
                        rb"cluster-gpl\x00[0-9]+(\.[0-9]+)?(\.[0-9]+)?\-ndb\-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?)"
                    ),
                    package="mysql-cluster",
                    purl_template="pkg:generic/mysql-cluster@{version}",
                    cpe_templates=[
                        "cpe:2.3:a:oracle:mysql_cluster:{version}:*:*:*:*:*:*:*",
                    ],
                ),
                Classifier(
                    # mysqld from MySQL Cluster after versioning aligned with MySQL Server
                    cls="mysqld-mysql-cluster-binary",
                    file_globs=[],
                    matcher=contents(
                        rb"/mysql-cluster-gpl-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)/"
                    ),
                    package="mysql-cluster",
                    purl_template="pkg:generic/mysql-cluster@{version}",
                    cpe_templates=[
                        "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
                        "cpe:2.3:a:oracle:mysql_server:{version}:*:*:*:*:*:*:*",
                        "cpe:2.3:a:oracle:mysql_cluster:{version}:*:*:*:*:*:*:*",
                    ],
                ),
                Classifier(
                    # mysqld from MySQL Server
                    cls="mysqld-mysql-server-binary",
                    file_globs=[],
                    matcher=contents(
                        rb"/mysql-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)/"
                    ),
                    package="mysql-server",
                    purl_template="pkg:generic/mysql-server@{version}",
                    cpe_templates=[
                        "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
                        "cpe:2.3:a:oracle:mysql_server:{version}:*:*:*:*:*:*:*",
                    ],
                ),
            ),
            package="",
            purl_template="",
            cpe_templates=[],
        ),
        Classifier(
            cls="ndbd-binary",
            file_globs=["**/ndbd"],
            matcher=contents(
                rb"/mysql-cluster-gpl-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)/"
            ),
            package="mysql-cluster",
            purl_template="pkg:generic/mysql-cluster@{version}",
            cpe_templates=["cpe:2.3:a:oracle:mysql_cluster:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="ndbmtd-binary",
            file_globs=["**/ndbmtd"],
            matcher=contents(
                rb"/mysql-cluster-gpl-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)/"
            ),
            package="mysql-cluster",
            purl_template="pkg:generic/mysql-cluster@{version}",
            cpe_templates=["cpe:2.3:a:oracle:mysql_cluster:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="ndb_mgmd-binary",
            file_globs=["**/ndb_mgmd"],
            matcher=contents(
                rb"/mysql-cluster-gpl-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)/"
            ),
            package="mysql-cluster",
            purl_template="pkg:generic/mysql-cluster@{version}",
            cpe_templates=["cpe:2.3:a:oracle:mysql_cluster:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="xtrabackup-binary",
            file_globs=["**/xtrabackup"],
            matcher=contents(
                rb"(?m).*/percona-xtrabackup-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)"
            ),
            package="percona-xtrabackup",
            purl_template="pkg:generic/percona-xtrabackup@{version}",
            cpe_templates=["cpe:2.3:a:percona:xtrabackup:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="mariadb-binary",
            file_globs=["**/{mariadb,mysql}"],
            matcher=any_of(
                # 10.6.15-MariaDB
                contents(
                    rb"(?m)(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)-MariaDB"
                ),
                # mariadb-11.8.5-2-redhat-x86_64/rhel-8/bin/mariadb
                contents(
                    rb"(?m)(?:^|/)mariadb-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)-"
                ),
            ),
            package="mariadb",
            purl_template="pkg:generic/mariadb@{version}",
            cpe_templates=["cpe:2.3:a:mariadb:mariadb:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="rust-standard-library-linux",
            file_globs=["**/libstd-????????????????.so"],
            # clang LLVM (rustc version 1.48.0 (7eac88abb 2020-11-16))
            matcher=contents(
                rb"(?m)(\x00)clang LLVM \(rustc version (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)"
            ),
            package="rust",
            purl_template="pkg:generic/rust@{version}",
            cpe_templates=["cpe:2.3:a:rust-lang:rust:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="rust-standard-library-macos",
            file_globs=["**/libstd-????????????????.dylib"],
            # c 1.48.0 (7eac88abb 2020-11-16)
            matcher=contents(
                rb"(?m)c (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)"
            ),
            package="rust",
            purl_template="pkg:generic/rust@{version}",
            cpe_templates=["cpe:2.3:a:rust-lang:rust:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="ruby-binary",
            file_globs=["**/ruby"],
            matcher=any_of(
                ruby_matcher,
                shared_library(r"^libruby\.so.*$", ruby_matcher),
            ),
            package="ruby",
            purl_template="pkg:generic/ruby@{version}",
            cpe_templates=["cpe:2.3:a:ruby-lang:ruby:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="erlang-binary",
            file_globs=["**/erlexec"],
            matcher=any_of(
                # [NUL]/usr/src/otp_src_25.3.2.6/erts/
                contents(
                    rb"(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/"
                ),
                # [NUL]/usr/local/src/otp-25.3.2.7/erts/
                contents(
                    rb"(?m)/usr/local/src/otp-(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/"
                ),
            ),
            package="erlang",
            purl_template="pkg:generic/erlang@{version}",
            cpe_templates=["cpe:2.3:a:erlang:erlang\\/otp:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="erlang-alpine-binary",
            file_globs=["**/beam.smp"],
            matcher=any_of(
                contents(
                    rb"(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/"
                ),
                contents(
                    rb"(?m)/usr/local/src/otp-(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/"
                ),
                # [NUL][NUL]26.1.2[NUL]...Erlang/OTP
                contents(
                    rb"\x00+(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)\x00+Erlang/OTP"
                ),
                # Erlang/OTP 17%s [erts-6.4.1.6] ...[NUL]17.5.6.9[NUL][NUL][NUL]
                contents(
                    rb"(?s)Erlang/OTP.{1,150}\x00+(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)\x00+"
                ),
            ),
            package="erlang",
            purl_template="pkg:generic/erlang@{version}",
            cpe_templates=["cpe:2.3:a:erlang:erlang\\/otp:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="erlang-library",
            file_globs=["**/liberts_internal.a"],
            matcher=any_of(
                contents(
                    rb"(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/"
                ),
                contents(
                    rb"(?m)/usr/local/src/otp-(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/"
                ),
            ),
            package="erlang",
            purl_template="pkg:generic/erlang@{version}",
            cpe_templates=["cpe:2.3:a:erlang:erlang\\/otp:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="swipl-binary",
            file_globs=["**/swipl"],
            matcher=contents(rb"(?m)swipl-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\/"),
            package="swipl",
            purl_template="pkg:generic/swipl@{version}",
            cpe_templates=["cpe:2.3:a:erlang:erlang\\/otp:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="dart-binary",
            file_globs=["**/dart"],
            # MathAtan[NUL]2.12.4 (stable) / Dart,GC"[NUL]3.6.0-216.1.beta (beta)
            matcher=contents(
                rb"(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+(\.[0-9]+)?\.beta)?) "
            ),
            package="dart",
            purl_template="pkg:generic/dart@{version}",
            cpe_templates=["cpe:2.3:a:dart:dart_software_development_kit:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="deno-binary",
            file_globs=["**/deno"],
            matcher=any_of(
                # Deno/2.6.3
                contents(rb"Deno/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
                # deno-65db94feba9d4d51a09b74629f566dbc90484fbarelease/v1.29.4windows
                contents(rb"deno-[0-9a-z]{40}release/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
                # deno-ab286750a8c87215a9651efb11fcc620f29140051.16.4release/vdlwindows
                contents(rb"deno-[0-9a-z]{40}(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
                # 1.10.31567c1013cc8ff12cf039137792da66a1d0015b5DENO_...
                contents(rb"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)[0-9a-z]{40}DENO"),
            ),
            package="deno",
            purl_template="pkg:generic/deno@{version}",
            cpe_templates=["cpe:2.3:a:deno:deno:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="haskell-ghc-binary",
            file_globs=["**/ghc*"],
            matcher=any_of(
                contents(rb"(?m)\x00GHC (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00"),
                # [NUL]libHSghc-8.10.4-ghc8.10.4.so[NUL]
                contents(
                    rb"\x00libHSghc\-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\-([a-zA-Z0-9]+\-)?ghc[0-9]+\.[0-9]+\.[0-9]+\.so\x00"
                ),
            ),
            package="haskell/ghc",
            purl_template="pkg:generic/haskell/ghc@{version}",
            cpe_templates=["cpe:2.3:a:haskell:ghc:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="haskell-cabal-binary",
            file_globs=["**/cabal"],
            matcher=any_of(
                contents(rb"(?m)\x00Cabal-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)-"),
                # /opt/cabal/1.22/lib/.../cabal-install-1.22.6.0-AfxbHivcmw40BMGrAXG3jJ
                contents(
                    rb"\x00.{0,50}cabal\-install\-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)\-[a-zA-Z0-9]+\x00+"
                ),
            ),
            package="haskell/cabal",
            purl_template="pkg:generic/haskell/cabal@{version}",
            cpe_templates=["cpe:2.3:a:haskell:cabal:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="haskell-stack-binary",
            file_globs=["**/stack"],
            matcher=contents(rb"(?m)Version\s*(?P<version>[0-9]+\.[0-9]+\.[0-9]+),\s*Git"),
            package="haskell/stack",
            purl_template="pkg:generic/haskell/stack@{version}",
            cpe_templates=["cpe:2.3:a:haskell:stack:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="consul-binary",
            file_globs=["**/consul"],
            matcher=any_of(
                # CONSUL_VERSION: 1.12.9
                contents(rb"CONSUL_VERSION: (?P<version>\d+\.\d+\.\d+)"),
                # GitDescribe=1.12.9"
                contents(rb"GitDescribe=(?P<version>\d+\.\d+\.\d+)\""),
                # [NUL][NUL][NUL]v1.7.14[NUL][NUL][NUL]
                contents(rb"\x00+v(?P<version>\d+\.\d+\.\d+)\x00+"),
            ),
            package="consul",
            purl_template="pkg:golang/github.com/hashicorp/consul@{version}",
            cpe_templates=["cpe:2.3:a:hashicorp:consul:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="hashicorp-vault-binary",
            file_globs=["**/vault"],
            matcher=any_of(
                # revoke1.18.0
                contents(rb"(?m)revoke(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
                # secondsindex_state1.20.0-rc1
                contents(rb"state(?P<version>[0-9]+\.[0-9]+\.[0-9]+\-rc[0-9])"),
                # ...0x%016x1.14.10...
                contents(rb"016x(?P<version>1.1[1,3,4].[0-9]{1,2})"),
                # [NUL][NUL][NUL]1.11.6[NUL][NUL][NUL]
                contents(rb"\x00+(?P<version>1\.[0-9][0,1]?\.[0-9]+)\x00+"),
            ),
            package="github.com/hashicorp/vault",
            purl_template="pkg:golang/github.com/hashicorp/vault@{version}",
            cpe_templates=["cpe:2.3:a:hashicorp:vault:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="nginx-binary",
            file_globs=["**/nginx"],
            # [NUL]nginx version: nginx/1.25.1 / openresty/1.21.4.1
            matcher=contents(
                rb"(?m)(\x00|\?)nginx version: [^\/]+\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:\+\d+)?(?:-\d+)?)"
            ),
            package="nginx",
            purl_template="pkg:generic/nginx@{version}",
            cpe_templates=[
                "cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
            ],
        ),
        Classifier(
            cls="bash-binary",
            file_globs=["**/bash"],
            # @(#)Bash version 5.2.15(1) release GNU
            matcher=contents(
                rb"(?m)@\(#\)Bash version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\([0-9]\) [a-z0-9]+ GNU"
            ),
            package="bash",
            purl_template="pkg:generic/bash@{version}",
            cpe_templates=["cpe:2.3:a:gnu:bash:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            # glance enhancement: Syft gates only "**/openssl" (the CLI binary).
            # We deliberately also gate the shared libraries, because the version
            # string "OpenSSL X" lives in libcrypto/libssl too — and those are
            # exactly the unmanaged copies an agent ships that OSV/Trivy miss.
            cls="openssl-binary",
            file_globs=["**/openssl", "**/libcrypto.so*", "**/libssl.so*"],
            matcher=branching(
                Classifier(
                    cls="openssl-binary-aws-lc",
                    file_globs=[],
                    # [NUL]OpenSSL 1.1.1 (compatible; AWS-LC 1.69.0)[NUL]
                    matcher=contents(rb"AWS-LC (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\)\x00"),
                    package="aws-lc",
                    purl_template="pkg:generic/aws-lc@{version}",
                    cpe_templates=["cpe:2.3:a:amazon:aws_libcrypto:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="openssl-binary",
                    file_globs=[],
                    # [NUL]OpenSSL 3.1.4' / [NUL]OpenSSL 1.1.1w'
                    matcher=contents(
                        rb"\x00OpenSSL (?P<version>[0-9]+\.[0-9]+\.[0-9]+([a-z]+|-alpha[0-9]|-beta[0-9]|-rc[0-9])?)"
                    ),
                    package="openssl",
                    purl_template="pkg:generic/openssl@{version}",
                    cpe_templates=["cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*"],
                ),
            ),
            package="",
            purl_template="",
            cpe_templates=[],
        ),
        Classifier(
            cls="openldap-search-binary",
            file_globs=["**/ldapsearch"],
            # $OpenLDAP: ldapsearch 2.4.45'
            matcher=contents(rb"\$OpenLDAP:\sldapsearch\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            package="openldap",
            purl_template="pkg:generic/openldap@{version}",
            cpe_templates=["cpe:2.3:a:openldap:openldap:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="qt-qtbase-lib",
            file_globs=["**/libQt*Core.so*"],
            matcher=any_of(
                # [NUL][NUL]Qt 6.5.0 (x86_64-little_endian-...
                contents(rb"\x00\x00Qt (?P<version>[0-9]+\.[0-9]+\.[0-9]+) \("),
                # QtCore library version 4.8.7
                contents(rb"QtCore library version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            ),
            package="qtbase",
            purl_template="pkg:generic/qtbase@{version}",
            cpe_templates=[
                "cpe:2.3:a:qt:qt:{version}:*:*:*:*:*:*:*",
                "cpe:2.3:a:qt:qtbase:{version}:*:*:*:*:*:*:*",
            ],
        ),
        Classifier(
            cls="gcc-binary",
            file_globs=["**/gcc"],
            # GCC: \(GNU\)  12.3.0'
            matcher=contents(rb"GCC: \(GNU\) (?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            package="gcc",
            purl_template="pkg:generic/gcc@{version}",
            cpe_templates=["cpe:2.3:a:gnu:gcc:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="fluent-bit-binary",
            file_globs=["**/fluent-bit"],
            # [NUL]3.0.2[NUL]%sFluent Bit / [NUL]2.2.3[NUL]Fluent Bit
            matcher=contents(
                rb"\x00(\x00)?(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00(\x1b\[1m\x00|\x00|\x00\x00)?(%s)?Fluent"
            ),
            package="fluent-bit",
            purl_template="pkg:github/fluent/fluent-bit@{version}",
            cpe_templates=["cpe:2.3:a:treasuredata:fluent_bit:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="wordpress-cli-binary",
            file_globs=["**/wp"],
            # wp-cli/wp-cli 2.9.0'
            matcher=contents(rb"(?m)wp-cli/wp-cli (?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            package="wp-cli",
            purl_template="pkg:generic/wp-cli@{version}",
            cpe_templates=["cpe:2.3:a:wp-cli:wp-cli:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="curl-binary",
            file_globs=["**/curl"],
            matcher=contents(rb"curl/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            package="curl",
            purl_template="pkg:generic/curl@{version}",
            cpe_templates=["cpe:2.3:a:haxx:curl:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="lighttpd-binary",
            file_globs=["**/lighttpd"],
            matcher=contents(rb"\x00lighttpd/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00"),
            package="lighttpd",
            purl_template="pkg:generic/lighttpd@{version}",
            cpe_templates=["cpe:2.3:a:lighttpd:lighttpd:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="proftpd-binary",
            file_globs=["**/proftpd"],
            matcher=contents(rb"\x00ProFTPD Version (?P<version>[0-9]+\.[0-9]+\.[0-9]+[a-z]?)\x00"),
            package="proftpd",
            purl_template="pkg:generic/proftpd@{version}",
            cpe_templates=["cpe:2.3:a:proftpd:proftpd:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="zstd-binary",
            file_globs=["**/zstd"],
            matcher=contents(rb"\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00"),
            package="zstd",
            purl_template="pkg:generic/zstd@{version}",
            cpe_templates=["cpe:2.3:a:facebook:zstandard:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="xz-binary",
            file_globs=["**/xz"],
            matcher=contents(rb"\x00xz \(XZ Utils\) (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00"),
            package="xz",
            purl_template="pkg:generic/xz@{version}",
            cpe_templates=["cpe:2.3:a:tukaani:xz:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="gzip-binary",
            file_globs=["**/gzip"],
            matcher=contents(rb"\x00(?P<version>[0-9]+\.[0-9]+)\x00"),
            package="gzip",
            purl_template="pkg:generic/gzip@{version}",
            cpe_templates=["cpe:2.3:a:gnu:gzip:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="sqlcipher-binary",
            file_globs=["**/sqlcipher"],
            matcher=contents(rb"[^0-9]\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00"),
            package="sqlcipher",
            purl_template="pkg:generic/sqlcipher@{version}",
            cpe_templates=["cpe:2.3:a:zetetic:sqlcipher:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="jq-binary",
            file_globs=["**/jq"],
            matcher=contents(rb"\x00(?P<version>[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]+)?)\x00"),
            package="jq",
            purl_template="pkg:generic/jq@{version}",
            cpe_templates=["cpe:2.3:a:jqlang:jq:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="chrome-binary",
            file_globs=["**/chrome"],
            # [NUL]127.0.6533.119[NUL]Default
            matcher=contents(rb"\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\x00Default"),
            package="chrome",
            purl_template="pkg:generic/chrome@{version}",
            cpe_templates=["cpe:2.3:a:google:chrome:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="ffmpeg-binary",
            file_globs=["**/ffmpeg"],
            # "%s version 7.1.1" -> "ffmpeg version 7.1.1"
            matcher=contents(rb"(?m)%s version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)"),
            package="ffmpeg",
            purl_template="pkg:generic/ffmpeg@{version}",
            cpe_templates=["cpe:2.3:a:ffmpeg:ffmpeg:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="ffmpeg-library",
            file_globs=["**/libav*"],
            matcher=any_of(
                contents(rb"(?m)FFmpeg version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)"),
                contents(rb"(?m)Lavc(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
                contents(rb"(?m)Lavf(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"),
            ),
            package="ffmpeg",
            purl_template="pkg:generic/ffmpeg@{version}",
            cpe_templates=["cpe:2.3:a:ffmpeg:ffmpeg:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="ffmpeg-library",
            file_globs=["**/libswresample*"],
            matcher=contents(rb"(?m)FFmpeg version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)"),
            package="ffmpeg",
            purl_template="pkg:generic/ffmpeg@{version}",
            cpe_templates=["cpe:2.3:a:ffmpeg:ffmpeg:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="elixir-binary",
            file_globs=["**/elixir"],
            matcher=contents(
                rb"(?m)ELIXIR_VERSION=(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:\.[0-9]+)?)?)"
            ),
            package="elixir",
            purl_template="pkg:generic/elixir@{version}",
            cpe_templates=["cpe:2.3:a:elixir-lang:elixir:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="elixir-library",
            file_globs=["**/elixir/ebin/elixir.app"],
            matcher=contents(
                rb'(?m)\{vsn,"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:\.[0-9]+)?)?)"\}'
            ),
            package="elixir",
            purl_template="pkg:generic/elixir@{version}",
            cpe_templates=["cpe:2.3:a:elixir-lang:elixir:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="istio-binary",
            file_globs=["**/pilot-discovery"],
            matcher=any_of(
                # [NUL]1.26.8[NUL][NUL]1.26.8[NUL]
                contents(
                    rb"[0-9]+\.[0-9]+\.[0-9]+\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+"
                ),
                # Clean[NUL][NUL][NUL]1.8.0[NUL]
                contents(
                    rb"Clean\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+"
                ),
                # Modified[NUL]...1.10-dev[NUL][NUL][NUL]
                contents(rb"Modified\x00+(?P<version>[0-9]+\.[0-9]+-dev)\x00+"),
                # 1.1.17[NUL]...S=v<y5
                contents(
                    rb"(?s)(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+.{1,100}S?=v<y5"
                ),
            ),
            package="pilot-discovery",
            purl_template="pkg:generic/istio@{version}",
            cpe_templates=["cpe:2.3:a:istio:istio:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="istio-binary",
            file_globs=["**/pilot-agent"],
            matcher=any_of(
                contents(
                    rb"[0-9]+\.[0-9]+\.[0-9]+\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+"
                ),
                contents(
                    rb"Clean\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+"
                ),
                contents(rb"Modified\x00+(?P<version>[0-9]+\.[0-9]+-dev)\x00+"),
                contents(
                    rb"(?s)(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha\.[0-9]+|-beta\.[0-9]+|-rc\.[0-9]+|-dev)?)\x00+.{1,100}S?=v<y5"
                ),
            ),
            package="pilot-agent",
            purl_template="pkg:generic/istio@{version}",
            cpe_templates=["cpe:2.3:a:istio:istio:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="grafana-binary",
            file_globs=["**/grafana"],
            matcher=any_of(
                # [NUL][NUL][NUL][NUL]12.2.0-258092[NUL][NUL][NUL][NUL]
                contents(rb"\x00+(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+\-[0-9]{6,})\x00+"),
                # [NUL][NUL][NUL][NUL]release-12.3.2+security-01[NUL][NUL][NUL][NUL]
                contents(
                    rb"\x00+release-(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+"
                ),
                # ...go1.21.8[NUL]...11.0.0-preview[NUL]...+DT
                contents(
                    rb"(?s)\x00+go1\.[0-9]+\.[0-9]+\x00+(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+.{1,500}\+DT"
                ),
                # HEAD[NUL][NUL][NUL][NUL]12.0.0[NUL][NUL]$a
                contents(
                    rb"(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+\$a"
                ),
                # [NUL]0xDC0xBF10.4.19[NUL]
                contents(
                    rb"\x00.(?P<version>10\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00"
                ),
                # 10.3.12[NUL]...go1.22.7[NUL]...+DT
                contents(
                    rb"(?s)(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+.{1,100}\x00go1\.[0-9]+\.[0-9]+\x00.{1,100}\+DT"
                ),
                # 9.5.21[NUL][NUL]v9.5.x[NUL]...$a
                contents(
                    rb"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+v[0-9]+\.[0-9]+\.x\x00+"
                ),
                # HEAD[NUL][NUL][NUL][NUL]9.2.20[NUL][NUL][NUL][NUL]
                contents(
                    rb"HEAD\x00+.*\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+"
                ),
                # 1b0f5f0a81[NUL]...9.4.0-beta1[NUL]...../usr/local/go
                contents(
                    rb"[a-z0-9]+\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test|-preview)?)(\+security-[0-9]+)?\x00+\/usr\/local\/go"
                ),
            ),
            package="grafana",
            purl_template="pkg:generic/grafana@{version}",
            cpe_templates=["cpe:2.3:a:grafana:grafana:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="grafana-binary",
            file_globs=["**/grafana-server"],
            matcher=any_of(
                # 78f0340031[NUL]...9.3.0-beta1[NUL]...../usr/local/go
                contents(
                    rb"[a-z0-9]+\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test)?)\x00+\/usr\/local\/go"
                ),
                # HEAD[NUL][NUL][NUL][NUL]9.0.0[NUL]:[NUL]
                contents(
                    rb"HEAD\x00+.*\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test)?)\x00+"
                ),
                # [NUL]...6.7.0-test[NUL]...../usr/local/go
                contents(
                    rb"(?s)\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+(-beta[0-9]|-test)?)\x00+.*\x00+.{1,1000}\x00+\/u"
                ),
            ),
            package="grafana",
            purl_template="pkg:generic/grafana@{version}",
            cpe_templates=["cpe:2.3:a:grafana:grafana:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="envoy-binary",
            file_globs=["**/envoy"],
            matcher=any_of(
                # [NUL]1.36.4[NUL]...envoy_reloadable_features
                contents(
                    rb"(?s)\x00(?P<version>1\.3[0-9]\.[0-9]+(-dev)?)\x00.{0,1000}envoy_reloadable_features"
                ),
                contents(rb"(?s)\x00(?P<version>1\.34\.5)\x00.{0,200}envoy\.reloadable_features"),
                # envoy_quic_...[NUL]1.28.7[NUL]
                contents(rb"(?s)envoy_quic_.{0,1000}\x00(?P<version>1\.2[0-9]\.[0-9]+(-dev)?)\x00"),
                # [NUL]1.20.7[NUL]Unable to
                contents(
                    rb"(?s)\x00(?P<version>1\.[12][0-9]\.[0-9]+(-dev)?)\x00.{0,1000}Unable to"
                ),
                # [NUL]1.22.11[NUL]...ValidationError
                contents(
                    rb"(?s)\x00(?P<version>1\.2[0-9]\.[0-9]+(-dev)?)\x00.{0,580}ValidationError"
                ),
                contents(
                    rb"(?s)\x00(?P<version>1\.1[0-9]\.[0-9]+(-dev)?)\x00.{0,1000}ValidationError"
                ),
                # [source...[NUL]1.11.0[NUL]/
                contents(rb"(?s)\[source/.{0,200}\x00(?P<version>1\.1[0-9]\.[0-9]+(-dev)?)\x00"),
                # [NUL]1.6.0[NUL]RELEASE
                contents(rb"(?s)\x00(?P<version>1\.[0-9]\.[0-9]+(-dev)?)\x00.{0,20}RELEASE"),
            ),
            package="envoy",
            purl_template="pkg:generic/envoy@{version}",
            cpe_templates=["cpe:2.3:a:envoyproxy:envoy:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="mongodb-binary",
            file_globs=["**/mongod"],
            matcher=any_of(
                # 6.0.27[NUL]tcmalloc
                contents(rb"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00tcmalloc"),
                # 7.0.28[NUL]heap_size
                contents(rb"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+heap_size"),
                # 8.0.17[NUL]cppdefines
                contents(rb"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+cppdefines"),
            ),
            package="mongodb",
            purl_template="pkg:generic/mongodb@{version}",
            cpe_templates=["cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="ingress-nginx-binary",
            file_globs=["**/nginx-ingress-controller"],
            matcher=any_of(
                # [NUL][NUL]v1.15.1[NUL][NUL]...go1.26.1[NUL][NUL][NUL]
                contents(
                    rb"v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+.{0,50}go[0-9]+\.[0-9]+(\-(alpha|beta)\.[0-9])?\.[0-9]+\x00+"
                ),
                # ?Lv1.9.6[NUL][NUL]$a...
                contents(
                    rb"v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\-(alpha|beta)\.[0-9])?)\x00+.{0,800}\$a.{0,10}\x00+"
                ),
                # [NUL][NUL]v1.7.1[NUL][NUL][NUL]...S=v<y5...
                contents(
                    rb"\x00+v?(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\-(alpha|beta)\.[0-9])?)\x00+.{0,100}S=v<y5"
                ),
                # [NUL][NUL]go1.22.8[NUL]...v1.12.0-beta.0[NUL][NUL]
                contents(
                    rb"\x00+go[0-9]+\.[0-9]+\.[0-9]+\x00+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\-(alpha|beta)\.[0-9])?)\x00+"
                ),
                # [NUL][NUL]v1.2.0-beta.1[NUL][NUL]
                contents(rb"\x00+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+\-(alpha|beta)\.[0-9])\x00+"),
            ),
            package="nginx-ingress-controller",
            purl_template="pkg:generic/nginx-ingress-controller@{version}",
            cpe_templates=["cpe:2.3:a:kubernetes:ingress-nginx:{version}:*:*:*:*:*:*:*"],
        ),
        Classifier(
            cls="elastic-agent-binary",
            file_globs=["**/elastic-agent"],
            matcher=any_of(
                # configenroll9.0.0-headeruint16secret
                contents(rb"enroll(?:: true)?(?P<version>[0-9]+\.[0-9]+\.[0-9]+)-?header"),
                # 3:04PM8.11.2:https
                contents(rb"PM(?P<version>[0-9]+\.[0-9]+\.[0-9]+):https"),
            ),
            package="elastic-agent",
            purl_template="pkg:generic/elastic-agent@{version}",
            cpe_templates=["cpe:2.3:a:elastic:elastic_agent:{version}:*:*:*:*:*:*:*"],
        ),
    ]

    return classifiers + _default_java_classifiers()


def _default_java_classifiers() -> list[Classifier]:
    """Return the Java/JVM binary classifiers, in Syft order."""
    return [
        Classifier(
            cls="java-binary",
            file_globs=["**/java"],
            matcher=branching(
                Classifier(
                    cls="java-binary-graalvm",
                    file_globs=[],
                    matcher=contents(
                        rb"(?m)\x00(?P<version>[0-9]+[.0-9]+[.0-9]+\+[0-9]+-jvmci-[0-9]+[.0-9]+-b[0-9]+)\x00"
                    ),
                    package="graalvm",
                    purl_template="pkg:generic/oracle/graalvm@{version}",
                    cpe_templates=["cpe:2.3:a:oracle:graalvm:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="java-binary-openjdk-zulu",
                    file_globs=[],
                    matcher=all_of(
                        path_glob("**/*zulu*/**"),
                        any_of(
                            # [NUL]openjdk[NUL]java[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
                            contents(
                                rb"(?m)\x00java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00"
                            ),
                            # arm64: [NUL]0.0[NUL]...11.0.22+7[NUL]...openjdk[NUL]java[NUL]
                            contents(
                                rb"(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>[0-9]+[^\x00]+)\x00+(openjdk|java)"
                            ),
                        ),
                    ),
                    package="zulu",
                    purl_template="pkg:generic/azul/zulu@{version}",
                    cpe_templates=["cpe:2.3:a:azul:zulu:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="java-binary-openjdk-with-update",
                    file_globs=[],
                    matcher=any_of(
                        contents(
                            rb"openjdk",
                            # [NUL]openjdk[NUL]java[NUL]1.8[NUL]1.8.0_352-b08[NUL]
                            rb"(?m)java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>(?P<primary>[0-9]+[^\x00]+)_(?P<update>[^\x00]+)-[^\x00]+)\x00",
                        ),
                        contents(
                            rb"openjdk",
                            # arm64: [NUL]0.0[NUL]...1.8.0_352-b08[NUL]...openjdk[NUL]java
                            rb"(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>(?P<primary>[0-9]+[^\x00]+)_(?P<update>[^\x00]+)-[^\x00]+)\x00+openjdk\x00java",
                        ),
                    ),
                    package="openjdk",
                    purl_template="pkg:generic/oracle/openjdk@{version}",
                    cpe_templates=[
                        "cpe:2.3:a:oracle:openjdk:{version}:update{{.update}}:*:*:*:*:*:*"
                    ],
                ),
                Classifier(
                    cls="java-binary-openjdk",
                    file_globs=[],
                    matcher=any_of(
                        # [NUL]openjdk[NUL]java[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
                        contents(
                            rb"(?m)\x00openjdk\x00java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00"
                        ),
                        # arm64: [NUL]0.0[NUL]...11.0.22+7[NUL]...openjdk[NUL]java
                        contents(
                            rb"(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>[0-9]+[^\x00]+)\x00+openjdk\x00java"
                        ),
                    ),
                    package="openjdk",
                    purl_template="pkg:generic/oracle/openjdk@{version}",
                    cpe_templates=["cpe:2.3:a:oracle:openjdk:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="java-binary-ibm",
                    file_globs=[],
                    matcher=all_of(
                        any_of(
                            path_glob("**/ibm/**"),
                            shared_library(
                                r"^libjli\.so$",
                                contents(rb"IBM_JAVA"),
                            ),
                        ),
                        # [NUL]java[NUL]1.8[NUL][NUL][NUL]1.8.0-foreman_2022_01_20_09_33-b00[NUL]
                        contents(
                            rb"(?m)\x00java\x00+(?P<release>[0-9]+[.0-9]+)\x00+(?P<version>[0-9]+[-._a-zA-Z0-9]+)\x00"
                        ),
                    ),
                    package="java",
                    purl_template="pkg:generic/ibm/java@{version}",
                    cpe_templates=["cpe:2.3:a:ibm:java:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="java-binary-openjdk-fallthrough",
                    file_globs=[],
                    matcher=contents(
                        rb"openjdk",
                        # [NUL]19.0.1+10-21[NUL]
                        rb"(?m)\x00(?P<version>[0-9]+[.0-9]+[+][-0-9]+)\x00",
                    ),
                    package="jre",
                    purl_template="pkg:generic/oracle/jre@{version}",
                    cpe_templates=["cpe:2.3:a:oracle:jre:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="java-binary-oracle",
                    file_globs=[],
                    # [NUL]19.0.1+10-21[NUL] / java[NUL]1.8[NUL]1.8.0_451-b10
                    matcher=contents(rb"(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[-._+a-zA-Z0-9]+)\x00"),
                    package="jre",
                    purl_template="pkg:generic/oracle/jre@{version}",
                    cpe_templates=["cpe:2.3:a:oracle:jre:{version}:*:*:*:*:*:*:*"],
                ),
            ),
            package="",
            purl_template="",
            cpe_templates=[],
        ),
        Classifier(
            cls="java-jdb-binary",
            file_globs=["**/jdb"],
            matcher=branching(
                Classifier(
                    cls="java-binary-graalvm",
                    file_globs=[],
                    matcher=contents(
                        rb"(?m)\x00(?P<version>[0-9]+[.0-9]+[.0-9]+\+[0-9]+-jvmci-[0-9]+[.0-9]+-b[0-9]+)\x00"
                    ),
                    package="graalvm",
                    purl_template="pkg:generic/oracle/graalvm@{version}",
                    cpe_templates=["cpe:2.3:a:oracle:graalvm_for_jdk:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="jdb-binary-openjdk-zulu",
                    file_globs=[],
                    matcher=all_of(
                        path_glob("**/*zulu*/**"),
                        any_of(
                            # [NUL]jdb[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
                            contents(
                                rb"(?m)(java|jdb)\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00"
                            ),
                            # arm64: [NUL]0.0[NUL]...11.0.22+7[NUL]...jdb
                            contents(
                                rb"(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>[0-9]+[^\x00]+)\x00+(java|jdb)"
                            ),
                        ),
                    ),
                    package="zulu",
                    purl_template="pkg:generic/azul/zulu@{version}",
                    cpe_templates=["cpe:2.3:a:azul:zulu:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="java-jdb-binary-openjdk",
                    file_globs=[],
                    matcher=all_of(
                        # [NUL]openjdk[NUL]java[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
                        contents(
                            rb"(?m)\x00openjdk\x00java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00"
                        ),
                        # arm64: [NUL]0.0[NUL]...11.0.22+7[NUL]...openjdk[NUL]java
                        contents(
                            rb"(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>[0-9]+[^\x00]+)\x00+openjdk\x00java"
                        ),
                    ),
                    package="openjdk",
                    purl_template="pkg:generic/oracle/openjdk@{version}",
                    cpe_templates=["cpe:2.3:a:oracle:openjdk:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="java-sdk-binary-ibm",
                    file_globs=[],
                    matcher=all_of(
                        any_of(
                            path_glob("**/ibm/**"),
                            shared_library(
                                r"^libjli\.so$",
                                contents(rb"IBM_JAVA"),
                            ),
                        ),
                        # [NUL]java[NUL]./lib/tools.jar...[NUL][NUL]1.8.0-foreman_..-b00[NUL]
                        contents(rb"(?m)\x00java\x00.+?\x00(?P<version>[0-9]+[-._a-zA-Z0-9]+)\x00"),
                    ),
                    package="java_sdk",
                    purl_template="pkg:generic/ibm/java_sdk@{version}",
                    cpe_templates=["cpe:2.3:a:ibm:java_sdk:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="java-binary-openjdk-fallthrough",
                    file_globs=[],
                    matcher=all_of(
                        contents(
                            rb"openjdk",
                            rb"(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\+[0-9]+)?([-._a-zA-Z0-9]+)?)\x00",
                        ),
                    ),
                    package="openjdk",
                    purl_template="pkg:generic/oracle/openjdk@{version}",
                    cpe_templates=["cpe:2.3:a:oracle:openjdk:{version}:*:*:*:*:*:*:*"],
                ),
                Classifier(
                    cls="java-binary-jdk",
                    file_globs=[],
                    matcher=contents(
                        rb"(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\+[0-9]+)?([-._a-zA-Z0-9]+)?)\x00"
                    ),
                    package="jdk",
                    purl_template="pkg:generic/oracle/jdk@{version}",
                    cpe_templates=["cpe:2.3:a:oracle:jdk:{version}:*:*:*:*:*:*:*"],
                ),
            ),
            package="",
            purl_template="",
            cpe_templates=[],
        ),
    ]
