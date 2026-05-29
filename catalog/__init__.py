# Packaging shim only. The rule catalogue is a directory of YAML files, not a
# Python package — but a `pip install` wheel needs a package to attach the
# YAML as package-data so the installed `tf-analyze` console script can find
# the rules. pyproject.toml maps the `tf_analyze_catalog` package to this dir
# and ships `*.yaml`/`*.md` as package-data; `detect._default_catalog_dir()`
# falls back to `Path(tf_analyze_catalog.__file__).parent` for installed use.
#
# Every other consumer (the source/dev layout, the bundled VS Code engine, the
# Docker image, the drift tests) globs `*.yaml` and ignores this file.
