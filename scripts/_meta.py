"""tf-analyze's own version — the single source of truth.

Read by the package build (`pyproject.toml` `[tool.setuptools.dynamic]`),
`--version`, SARIF `tool.driver.version`, the LSP `serverInfo` and the
JSON report's `tool_version`. The release workflow refuses a tag that
does not match it. Bump it here only.
"""

__version__ = "0.2.6"
