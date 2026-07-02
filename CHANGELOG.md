# Changelog

## [0.5.1](https://github.com/Limozacloud/glance/compare/glance-v0.5.0...glance-v0.5.1) (2026-07-02)


### Bug Fixes

* query plocate once per anchor (AND vs OR) ([#24](https://github.com/Limozacloud/glance/issues/24)) ([7326444](https://github.com/Limozacloud/glance/commit/7326444dc45645d20af62cb27b65bc4f7367007d))

## [0.5.0](https://github.com/Limozacloud/glance/compare/glance-v0.4.0...glance-v0.5.0) (2026-07-02)


### Features

* **binary:** annotate container context in minimal output ([#16](https://github.com/Limozacloud/glance/issues/16)) ([dc70e1b](https://github.com/Limozacloud/glance/commit/dc70e1bf0ef0df8afc52908c16a4380dc538f436))
* **output:** emit glance:container property in CycloneDX output ([#19](https://github.com/Limozacloud/glance/issues/19)) ([ab33934](https://github.com/Limozacloud/glance/commit/ab339346681fbabf5575cd0defd6d114c06c076c))
* **rpm:** include epoch in Component.version for full EVR ([#17](https://github.com/Limozacloud/glance/issues/17)) ([21d5e19](https://github.com/Limozacloud/glance/commit/21d5e196512afb9970b22a6603b103ff6f38e900))


### Documentation

* remove stale engine/mandatory_paths refs from cli and config docs ([#22](https://github.com/Limozacloud/glance/issues/22)) ([05ae32f](https://github.com/Limozacloud/glance/commit/05ae32f11c8c2c9d4426d6c40e0f857bb6957ab7))
* update README and internals docs to reflect plocate-required architecture ([#21](https://github.com/Limozacloud/glance/issues/21)) ([334e62b](https://github.com/Limozacloud/glance/commit/334e62bcfec1baf6d74e9b1b97ff42c00e8dad7d))

## [0.4.0](https://github.com/Limozacloud/glance/compare/glance-v0.3.0...glance-v0.4.0) (2026-06-30)


### Features

* installed-level ecosystem catalogers + gobinary + rpm/apk qualifiers ([#14](https://github.com/Limozacloud/glance/issues/14)) ([ecd0221](https://github.com/Limozacloud/glance/commit/ecd0221203d7ee9f1be2b2336ae19ef899eb7bc2))
* unified classifier_files format with cataloger routing ([#15](https://github.com/Limozacloud/glance/issues/15)) ([2ba7937](https://github.com/Limozacloud/glance/commit/2ba79376ee68a1f0d69b7bcd551d7da54bcc74f3))
* Windows SBOM catalogers — registry + PE binary with versioned CPEs ([#9](https://github.com/Limozacloud/glance/issues/9)) ([c4b61de](https://github.com/Limozacloud/glance/commit/c4b61dea8e560e82b6f285110663bb3d6f358d6a))


### Documentation

* fill gaps in config reference and default_config.yaml ([07fd035](https://github.com/Limozacloud/glance/commit/07fd0359fb504ee5f6830911bbd04381d8911363))

## [0.3.0](https://github.com/Limozacloud/glance/compare/glance-v0.2.0...glance-v0.3.0) (2026-06-18)


### Features

* surface third-party-bundled libraries instead of suppressing them ([#5](https://github.com/Limozacloud/glance/issues/5)) ([0dee4c6](https://github.com/Limozacloud/glance/commit/0dee4c64e558bef54425373bdae65fe829a60eec))

## [0.2.0](https://github.com/Limozacloud/glance/compare/glance-v0.1.0...glance-v0.2.0) (2026-06-18)


### Features

* add binary SBOM cataloger with package correlation ([#1](https://github.com/Limozacloud/glance/issues/1)) ([d247c73](https://github.com/Limozacloud/glance/commit/d247c73d592c0e7d0540ce3479a27caa161d08b4))
* add libtiff/curl/expat/pcre2/libssh/libpng/libarchive .so classifiers ([#4](https://github.com/Limozacloud/glance/issues/4)) ([f2bae37](https://github.com/Limozacloud/glance/commit/f2bae3722e26bf534619f514d7aa64de505fe4ed))
* load binary classifiers from external YAML/JSON files ([#3](https://github.com/Limozacloud/glance/issues/3)) ([90fffac](https://github.com/Limozacloud/glance/commit/90fffac5e72f8893bc8864f6b8520ba9836ae074))
