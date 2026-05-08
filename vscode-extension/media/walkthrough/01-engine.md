## Connect the detection engine

`tf-analyze` is a frontend over a Python detection engine (`scripts/detect.py`) that ships with the [`tf-analyze` project](https://github.com/ChrisAdkin8/tf-analyze).

You have **three** options:

1. **Open the `tf-analyze` repo as part of your workspace** — the extension auto-discovers `scripts/detect.py`. ✅ Easiest.
2. **Set the path explicitly** — point `tf-analyze.scriptPath` at an absolute path to `detect.py`.
3. **Drop `detect.py` on your `$PATH`** — the extension will find it.

> **Requires:** Python 3.10+ on `PATH`. `python-hcl2` is optional but recommended.
