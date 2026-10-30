"""Git-diff / base-branch helpers for the ``--mode diff`` flow.

Three thin wrappers around ``git`` extracted from ``detect.py`` as the
**eleventh modularisation seam**. All three run ``git`` via
``subprocess`` and tolerate it being missing — when ``git`` isn't
available, ``get_diff_files`` returns an empty set so the caller can
gracefully fall back to a full scan.

Functions are named without the leading underscore (this module is
the canonical home now); detect.py re-exports them as their old
private names so existing call sites keep working without churn.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

# Round-5 audit fix #3 — every git subprocess call now carries a
# 30-second wall-clock cap. A hung git (corrupted repo, NFS stall, lock
# file held by another process, network drive freeze) used to leave
# the engine waiting forever. 30 s is generous for any realistic git
# command on a real workspace (sub-second in practice) and short
# enough that a freeze surfaces quickly with a clear stderr WARN
# instead of an indefinite hang.
_GIT_TIMEOUT_SEC = 30

class _CannotNarrow(Exception):
    """The change can't be narrowed to a set of files: the caller scans
    everything. The message says why."""


# `--ignore-submodules=none`: a `submodule.<name>.ignore = all` in
# `.gitmodules`, a file the PR controls, would drop the submodule from
# the list, and so hide its bump. Nothing else a PR commits changes which
# names `--name-only` lists: `.gitattributes` diff drivers aren't run for it.
_DIFF_FLAGS = ("-z", "--name-only", "--no-renames", "--ignore-submodules=none")

# A commit named by its full SHA-1 or SHA-256 hash.
_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")

# git finds its repository by walking up from the cwd, which is the scan
# target: files a pull request controls. A PR can commit a *bare* repo
# (`HEAD`, `config`, `objects/`, `refs/`: git refuses `.git` paths, not
# these) into the target. git would then read that repo: its blobs (a
# planted "base" for --inline-ignores-from / --mode diff) and its config,
# where `core.fsmonitor` (and other keys) run commands. Every git call
# refuses to discover a bare repo and never runs fsmonitor or hooks;
# `verified_work_tree` then checks the repo git did find.
_GIT_SAFETY = (
    "-c", "safe.bareRepository=explicit",
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
)

# For a git call that prints paths. Left alone, git writes a path with a
# non-ASCII byte, a quote or a newline as a quoted C string
# (`"caf\303\251/main.tf"`), which names no file, so the file was
# dropped. Pair with `-z` and read the output with `split_git_paths`.
GIT_RAW_PATHS = ("-c", "core.quotepath=off")


def _run_git(argv: list[str], target: Path, *, text: bool = False) -> subprocess.CompletedProcess | None:
    """Run a git subprocess with a timeout. Returns None on hang.

    Centralises the timeout + WARN-on-hang discipline so the four
    call sites below share one error path. Callers that need the
    `text=True` shape pass it through. Every call gets `_GIT_SAFETY`.
    A repository pinned with ``GIT_DIR`` / ``GIT_WORK_TREE`` in the
    environment is left to git (which then does no discovery).
    """
    if argv and argv[0] == "git":
        argv = ["git", *_GIT_SAFETY, *argv[1:]]
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=text,
            cwd=str(target),
            timeout=_GIT_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        sys.stderr.write(
            f"WARN: git command exceeded {_GIT_TIMEOUT_SEC}s and was killed: "
            f"{' '.join(argv)}\n"
        )
        return None


def split_git_paths(stdout: bytes | None) -> list[str]:
    """The paths in a `-z` git call's output (run it without ``text``).
    `os.fsdecode` keeps a name that isn't valid UTF-8, which a text-mode
    read would crash on, and `open` turns it back into the same bytes."""
    return [os.fsdecode(p) for p in (stdout or b"").split(b"\0") if p]


def _gitfile_target(dotgit: Path) -> Path | None:
    """Where a ``.git`` *file* (linked worktree, submodule) points."""
    try:
        first = dotgit.read_text().splitlines()[0]
    except (OSError, IndexError, UnicodeDecodeError):
        return None
    if not first.startswith("gitdir:"):
        return None
    return (dotgit.parent / first[len("gitdir:"):].strip()).resolve()


def verified_work_tree(target: Path) -> tuple[Path | None, str | None]:
    """``(work tree root, None)`` for the repository git uses from
    ``target``, or ``(None, reason)`` when there is none or it can't be
    trusted. Trusted means: pinned by ``GIT_WORK_TREE`` / ``GIT_DIR`` and
    git agrees with the pin; or else an ordinary checkout, whose git dir
    is the root's own ``.git`` folder (or what a ``.git`` file points
    at). A repo git found anywhere else, such as one a PR planted in the
    target with ``core.worktree`` pointing out of it, is refused."""
    cwd = target if target.is_dir() else target.parent
    try:
        res = _run_git(
            ["git", "rev-parse", "--show-toplevel", "--absolute-git-dir"], cwd, text=True,
        )
    except OSError as e:  # git not installed
        return None, f"git not available ({e})"
    if res is None or res.returncode != 0:
        return None, "not a git work tree" + _git_err(res)
    out = (res.stdout or "").splitlines()
    if len(out) != 2 or not out[0].strip() or not out[1].strip():
        return None, "not a git work tree"
    root = Path(out[0].strip()).resolve()
    git_dir = Path(out[1].strip()).resolve()
    pin_tree = os.environ.get("GIT_WORK_TREE")
    pin_dir = os.environ.get("GIT_DIR")
    # A relative pin is relative to the folder git runs in, not ours.
    if pin_tree and root != (cwd / pin_tree).resolve():
        return None, f"work tree {root} is not GIT_WORK_TREE {pin_tree}"
    if pin_dir:
        want = cwd / pin_dir
        want = (_gitfile_target(want) if want.is_file() else want.resolve())
        if want != git_dir:
            return None, f"git dir {git_dir} is not GIT_DIR {pin_dir}"
        return root, None
    dotgit = root / ".git"
    if dotgit.is_dir() and not dotgit.is_symlink():
        expected = dotgit.resolve()
    elif dotgit.is_file():
        expected = _gitfile_target(dotgit)
    else:
        expected = None
    if expected != git_dir:
        return None, f"git dir {git_dir} is not {root}/.git"
    return root, None


def auto_detect_base_branch(target: Path) -> str:
    """Return 'main' or 'master' depending on which the repo uses, else 'main'.

    Round-5 audit fix #17 — additionally surface a stderr WARN when
    every probed branch fails (typical cause: not in a git repo, or
    git is missing). Previously the function silently returned the
    default `"main"`, so the operator running `--mode diff` outside a
    git workspace saw "no findings" instead of a clear signal.
    """
    failures: list[str] = []
    for branch in ("main", "master"):
        try:
            result = _run_git(["git", "rev-parse", "--verify", branch], target)
        except OSError as e:  # git not installed
            failures.append(f"git not available ({e})")
            continue
        if result is None:
            continue
        if result.returncode == 0:
            return branch
        # Record the stderr for the final WARN if every probe failed.
        failures.append((result.stderr or b"").decode("utf-8", "replace").strip())
    if failures:
        sys.stderr.write(
            "WARN: git rev-parse failed for all probed base branches "
            f"(main, master): {failures[0] or '(empty stderr)'}\n"
        )
    return "main"


def find_latest_prior(reports_dir: Path, suffix: str = ".md") -> Path | None:
    """Most-recent ``tf-analysis-YYYY-MM-DD<suffix>`` under ``reports_dir``."""
    if not reports_dir.is_dir():
        return None
    # Audit item 8 — `glob()` returns a snapshot but `stat()` is called
    # later; a concurrent unlink between the two raises
    # `FileNotFoundError`. Tolerate it by skipping the missing entry
    # instead of crashing the whole scan.
    def _mtime_safe(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError:
            return -1.0
    candidates = sorted(
        (p for p in reports_dir.glob(f"tf-analysis-*{suffix}") if _mtime_safe(p) >= 0),
        key=_mtime_safe,
        reverse=True,
    )
    return candidates[0] if candidates else None


# A `variable` or `locals` block feeds every file in its folder (one
# Terraform module). Comments aren't skipped: a false match only widens
# the scan.
_SHARED_INPUT_RE = re.compile(r'^\s*(?:variable|locals)\b|"(?:variable|locals)"\s*:', re.M)


def _is_tf(fp: Path) -> bool:
    return fp.name.endswith((".tf", ".tf.json"))


def _is_tfvars(fp: Path) -> bool:
    return fp.name.endswith((".tfvars", ".tfvars.json"))


def _module_siblings(changed: set[Path]) -> set[Path]:
    """The `.tf` files sharing a folder with a changed file that feeds
    them: a `.tfvars`, a file declaring `variable` / `locals`, or a
    deleted file (which may have held a variable or a resource another
    check pairs with). Without this, a PR that only flips a variable
    default in `variables.tf` re-scanned `variables.tf` alone, and the
    resource using `var.x` in `main.tf` was never checked."""
    out: set[Path] = set()
    for fp in changed:
        if fp.exists() and not _is_tfvars(fp):
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = "variable"  # unreadable: widen rather than guess
            if not _SHARED_INPUT_RE.search(text):
                continue
        if fp.parent.is_dir():
            out.update(p.resolve() for p in fp.parent.iterdir() if p.is_file() and _is_tf(p))
    return out


def git_work_tree(target: Path) -> str | None:
    """Real path of the git work tree holding ``target``, as git itself
    reports it (``git rev-parse --show-toplevel`` run in ``target``, under
    `_run_git`'s timeout), or None outside a repository or without git.
    A stray ``.git`` entry in some parent folder is not taken for a
    repository."""
    root, _err = verified_work_tree(target)
    return str(root) if root is not None else None


def walk_tf_files(target: Path, *, contain: bool = False,
                  skipped: list | None = None,
                  followed: list | None = None,
                  keep: Callable[[Path], bool] | None = None,
                  opaque: list | None = None,
                  unknown: list | None = None) -> list[Path]:
    """The one way every scan path lists a target's `.tf` / `.tf.json`
    files (static, fleet, verify-fixed, diff scope): `tf_source_files`
    with its symlink policy. A symlinked folder that leaves the target is
    followed only inside the enclosing git work tree, and never with
    `contain` (fleet: targets may be untrusted repos). ``skipped`` /
    ``followed`` are filled as in `tf_source_files`.

    `.terraform` folders aren't walked, but `_cache_files_in_use` adds
    the files in them that are code, not a cache: those git tracks, and
    those a listed file calls as a local module. ``keep`` drops files
    from the list, so a file the scan won't read reaches nothing.
    ``opaque`` gets each `(file, source)` whose module folder can't be
    told (`module_sources`) while a `.terraform` folder is there.
    ``unknown`` gets each `.terraform` folder holding Terraform files when
    git can't say which it tracks: code committed there went unlisted."""
    from _tfjson import tf_source_files  # local: _tfjson is engine-side

    linked: list[str] = [] if followed is None else followed
    caches: list[Path] = []
    files = tf_source_files(
        target,
        follow_within=None if contain else git_work_tree(target),
        skipped=skipped, followed=linked, caches=caches,
    )
    if keep is not None:
        files = [fp for fp in files if keep(fp)]
    # No `.terraform` folder under the target: nothing to find, and no
    # second read of every file.
    if caches:
        files += _cache_files_in_use(files, target, caches, linked, keep, opaque, unknown)
    return files


def _cache_files_in_use(files: list[Path], target: Path, caches: list[Path],
                        linked: list[str], keep: Callable[[Path], bool] | None,
                        opaque: list | None, unknown: list | None) -> list[Path]:
    """The `.tf` files under the `.terraform` folders `caches` that are
    code, not a cache: those git tracks (`tracked_cache_files`), and those
    the listed files reach through local module calls, directly or through
    each other (`source = "./.terraform/m"`). Without git the second is
    all there is, so `opaque` reports what it couldn't follow.

    The search stays inside `target` and the folders in `linked` (the
    real paths of symlinked folders the walk followed), as the walk does:
    a `source` with enough `../` to leave them is not read."""
    root = target.resolve()
    tracked = tracked_cache_files(target, linked)
    if tracked is None and unknown is not None:
        unknown.extend(cache for cache in caches if _holds_terraform(cache))
    listed: list[Path] = []
    for cache in caches:
        top = cache.resolve()
        listed.extend(
            cache / fp.relative_to(top) for fp in sorted(tracked or ())
            if fp.is_relative_to(top) and _is_tf(fp) and fp.is_file()
        )
    if keep is not None:
        listed = [fp for fp in listed if keep(fp)]

    def in_cache(p: Path, base: Path) -> bool:
        return ".terraform" in (p.relative_to(base) if p.is_relative_to(base) else p).parts

    reached = _reachable([*files, *listed], within=[root, *map(Path, linked)],
                         keep=keep, opaque=opaque)
    return listed + sorted(
        fp for real, fp in reached.items() if in_cache(fp, target) or in_cache(real, root)
    )


def _tf_text(fp: Path) -> str | None:
    """Scannable text of a `.tf` (or rendered `.tf.json`) file, or None."""
    from _hcl import _read_normalized
    from _tfjson import read_tf_source

    try:
        return read_tf_source(fp, _read_normalized)
    except (OSError, ValueError):
        return None


def _holds_terraform(folder: Path) -> bool:
    """Is there a `.tf` or `.tfvars` file anywhere under ``folder``?"""
    return any(
        _is_tf(Path(name)) or _is_tfvars(Path(name))
        for _dir, _subdirs, names in os.walk(folder) for name in names
    )


def tracked_cache_files(target: Path, linked: list[str] = ()) -> set[Path] | None:
    """Every file git tracks in a `.terraform` folder under ``target`` or
    the real folders ``linked`` into it, as real paths. Nothing is a cache
    once it is committed: a pull request brought it, and a committed
    `.terraform/modules/modules.json` makes Terraform load it for any
    `source`, so it is scanned like other code. ``None`` when git can't
    say: no work tree the scan can trust, git missing, or a failed call.
    The list is filtered here, not by a pathspec: a linked folder's name
    can hold glob characters."""
    root, _err = verified_work_tree(target)
    if root is None:
        return None
    real_target = target.resolve()
    tops = [".", *(os.path.relpath(d, real_target) for d in dict.fromkeys(linked))]
    try:
        res = _run_git(
            ["git", "--literal-pathspecs", *GIT_RAW_PATHS, "ls-files", "-z", "--full-name",
             "--", *tops],
            target,
        )
    except OSError:  # git not installed
        return None
    if res is None or res.returncode != 0:
        return None
    return {
        root / name for name in split_git_paths(res.stdout)
        if ".terraform" in Path(name).parts
    }


# The label may be quoted or bare: `module a { ... }` is valid HCL too.
# `\s`: a masked comment can leave a newline before the `{`.
_MODULE_BLOCK_RE = re.compile(
    r'(?m)^[ \t]*module\s+(?:"[^"\n]*"|[A-Za-z_][\w-]*)\s*\{'
)
_SOURCE_ATTR_RE = re.compile(r'(?m)^[ \t]*source[ \t]*=(?!=)')
_NEXT_ARG_RE = re.compile(r'(?m)^[ \t]*\S')
# A string with no `${`, `%{` or `\` escape: its text is its value.
_PLAIN_STRING_RE = re.compile(r'"((?:[^"\\\n$%]|[$%](?!\{))*)"')


def _top_level(code: str, start: int, end: int) -> str:
    """``code[start:end]`` (a block body) with everything nested in it —
    sub-blocks, lists, calls, and strings inside those — blanked, so
    only the body's own arguments are left. Newlines are kept."""
    from _hcl import _string_end

    out = list(code[start:end])
    depth = 0
    i = start
    while i < end:
        ch = code[i]
        if ch == '"':
            j = min(_string_end(code, i), end)
            if depth:
                for k in range(i, j):
                    if out[k - start] != "\n":
                        out[k - start] = " "
            i = j
            continue
        if ch in "{[(":
            depth += 1
        if depth and ch != "\n":
            out[i - start] = " "
        if ch in "}])":
            depth = max(0, depth - 1)
        i += 1
    return "".join(out)


def module_sources(fp: Path, text: str) -> tuple[list[Path], list[str]]:
    """What `fp`'s `module` blocks call: the folders of its local modules
    (`source = "./modules/db"`), joined onto its folder, then the source
    expressions that aren't a plain string. Terraform accepts any constant
    (`("./m")`, `"${"./m"}"`, `true ? "./m" : "./n"`); they aren't
    evaluated here, so callers must treat the folder as unknown.

    A folder is cleaned as text, not resolved: Terraform removes `..`
    from `./link/../m` before it looks at the disk, so `..` does not
    undo `link`, whatever `link` points at.

    Only a `source` argument of a `module` block itself counts: comments
    and heredocs are masked first, and a `source` nested deeper (a
    `provisioner "file" { source = "./x" }`) or in another block is not
    a module call. `text` is HCL (a `.tf.json` rendered by `_tfjson`)."""
    from _hcl import brace_walk, mask_comments_and_heredocs

    code = mask_comments_and_heredocs(text)
    local: list[Path] = []
    opaque: list[str] = []
    for m in _MODULE_BLOCK_RE.finditer(code):
        end_after = brace_walk(code, m.end() - 1)
        if end_after is None:
            continue
        body = _top_level(code, m.end(), end_after - 1)
        for s in _SOURCE_ATTR_RE.finditer(body):
            # The value runs to the next argument: `_top_level` blanked
            # what a multi-line expression has on its later lines.
            after = _NEXT_ARG_RE.search(body, s.end())
            stop = after.start() if after else len(body)
            value = code[m.end() + s.end():m.end() + stop].strip()
            plain = _PLAIN_STRING_RE.fullmatch(value)
            if plain is None:
                # One line: this text reaches stderr, and a CI runner reads
                # a line starting `::error::` as a command.
                opaque.append(" ".join(value.split())[:120])
            elif plain.group(1).startswith(("./", "../")):
                local.append(Path(os.path.normpath(fp.parent / plain.group(1))))
    return local, opaque


def local_module_sources(fp: Path, text: str) -> list[Path]:
    """The local-module folders of `module_sources`. Shared by the diff
    scope below and by `applies_when` gating (a child runs under its
    caller's provider pins)."""
    return module_sources(fp, text)[0]


def _reachable(files: list[Path], *, within: list[Path] | None = None,
               keep: Callable[[Path], bool] | None = None,
               opaque: list | None = None) -> dict[Path, Path]:
    """The `.tf` files of every local module `files` call, recursively,
    other than `files`: real path -> the path Terraform reaches it by,
    which stays under the folder link it came through. Each folder is
    visited once, so modules calling each other can't loop. Nothing that
    resolves outside the real paths ``within`` is read or returned, and
    no file ``keep`` rejects, so an ignored module calls nothing. Each
    `(file, source)` that can't be followed is added to ``opaque``."""
    def allowed(p: Path) -> bool:
        return within is None or any(p.is_relative_to(r) for r in within)

    out: dict[Path, Path] = {}
    known = {fp.resolve() for fp in files}
    queue = list(files)
    seen_dirs: set[Path] = set()
    while queue:
        fp = queue.pop()
        text = _tf_text(fp)
        if text is None:
            continue
        local, odd = module_sources(fp, text)
        if opaque is not None:
            opaque.extend((fp, value) for value in odd)
        for src in local:
            try:
                child = src.resolve()
                if child in seen_dirs or not child.is_dir() or not allowed(child):
                    continue
                seen_dirs.add(child)
                found = [(p.resolve(), src / p.name) for p in child.iterdir()
                         if p.is_file() and _is_tf(p)]
            except (OSError, RuntimeError, ValueError):  # RuntimeError: a symlink loop
                if opaque is not None:
                    opaque.append((fp, str(src)))
                continue
            for real, spelled in found:
                if (real not in known and real not in out and allowed(real)
                        and (keep is None or keep(spelled))):
                    out[real] = spelled
                    queue.append(spelled)
    return out


def _with_local_children(files: set[Path]) -> set[Path]:
    """`files` plus the `.tf` files of every local module they call
    (`source = "./modules/db"`), recursively. A caller passes values into
    the child (`module "db" { public = var.public }`), so a change to the
    caller can change the child's findings."""
    return files | set(_reachable(list(files)))


def _with_local_callers(files: set[Path], tf_files: list[Path],
                        ignored: Callable[[Path], bool] | None = None) -> set[Path]:
    """`files` plus the `.tf` files of every folder (of `tf_files`, the
    target's files from `walk_tf_files`) that calls a folder of `files` as
    a local module (`source = "../net"`), recursively up the call chain.
    A child's outputs feed its caller (`security_groups =
    [module.net.sg_id]`), so a change to the child can change the
    caller's findings. A `source` that isn't a plain string could call
    any folder, so the scope can't be told: `_CannotNarrow`, unless the
    scan won't read that file anyway (``ignored``)."""
    callers: dict[Path, set[Path]] = {}  # child folder -> caller folders
    for fp in tf_files:
        text = _tf_text(fp)
        if text is None:
            continue
        local, opaque = module_sources(fp, text)
        if opaque and not (ignored is not None and ignored(fp)):
            raise _CannotNarrow(f"{str(fp)!r}: module source {opaque[0]} is not a plain string")
        for src in local:
            try:
                child = src.resolve()
            except (OSError, RuntimeError, ValueError):
                continue  # a symlink loop or a bad name: no folder to call
            callers.setdefault(child, set()).add(fp.parent.resolve())
    out = set(files)
    queue = list({fp.parent for fp in files})
    seen = set(queue)
    while queue:
        for caller in callers.get(queue.pop(), ()):
            if caller in seen:
                continue
            seen.add(caller)
            queue.append(caller)
            out.update(p.resolve() for p in caller.iterdir() if p.is_file() and _is_tf(p))
    return out


def _changed_path(fp: Path) -> Path:
    """Real path of a path git says changed. A folder here is a folder
    link or a submodule (git lists files, never a plain folder): git names
    only that, so the files that changed behind it are unknown. A symlink
    that loops has no real path. Both are `_CannotNarrow`."""
    try:
        if fp.is_dir():
            raise _CannotNarrow(f"{str(fp)!r} is a folder link or submodule")
        try:
            return fp.resolve(strict=True)  # only `strict` refuses a loop on every Python
        except (FileNotFoundError, NotADirectoryError):
            return fp.resolve()  # deleted
    except (OSError, RuntimeError, ValueError) as e:  # RuntimeError: a symlink loop
        raise _CannotNarrow(f"{str(fp)!r}: {e}") from e


def get_diff_files(target: Path, diff_base: str,
                   ignored: Callable[[Path], bool] | None = None) -> set[Path] | None:
    """Set of files to scan for the change between ``diff_base`` and HEAD:
    the changed ``.tf`` files, the folder-mates of a changed file that
    feeds them (`_module_siblings`), the local modules any of those call
    (`_with_local_children`), the folders under ``target`` that call any
    of their folders as a local module (`_with_local_callers`), and every
    other changed file, so a changed `.tfvars` or workflow file is scanned
    by the rules that read it (`_collect_extra_files`) and an unchanged
    one adds no noise. Renames count as a delete plus an add
    (``--no-renames``), so the folder a file left is covered too. Nothing
    can be narrowed from a changed folder link or submodule, or while a
    module `source` isn't a plain string (`_CannotNarrow`): git names only
    the link, and the files behind it changed unseen. ``ignored``
    says which files the scan won't read (`ignore_paths`).

    Three sources are unioned:

    * ``git diff -z --name-only <base>...HEAD`` (the canonical three-dot
      diff, falls back to two-dot if the merge-base lookup fails).
    * ``git ls-files -z --others --exclude-standard`` for untracked files.
    * Every result is resolved against the repo's git root so the
      caller gets absolute paths that survive any later ``chdir``.

    Returns ``None`` when the diff could not be computed — git missing,
    a git call failed or timed out, the base ref is unknown (e.g. not
    fetched in a shallow CI checkout), or `_CannotNarrow`. An empty set
    means the diff ran and nothing changed; the two must not be confused,
    or a failed diff would scan nothing and pass a CI gate. The caller
    falls back to a full scan.
    """
    root, err = verified_work_tree(target)
    if root is None:
        print(f"WARN: cannot diff: {err}", file=sys.stderr)
        return None
    try:
        # The pathspecs are relative to `target` (git's cwd), so a module
        # linked in from outside it (`net -> ../shared`, followed by
        # `walk_tf_files`) needs its own: `../shared`. Changed files come
        # back as real paths; the scan matches them by resolved path.
        followed: list[str] = []
        unknown: list[Path] = []
        tf_files = walk_tf_files(target, followed=followed, unknown=unknown)
        if unknown:
            raise _CannotNarrow(f"cannot list the files git tracks in {str(unknown[0])!r}")
        real_target = target.resolve()
        pathspecs = [".", *(os.path.relpath(d, real_target) for d in dict.fromkeys(followed))]
        # All git calls below go through `_run_git`, which applies the
        # 30-second timeout. A None return means the call hung past
        # the cap — report the diff as failed (caller: full scan).
        result = _run_git(
            ["git", *GIT_RAW_PATHS, "diff", *_DIFF_FLAGS, f"{diff_base}...HEAD",
             "--", *pathspecs],
            target,
        )
        if result is None:
            return None
        if result.returncode != 0:
            # Fall back to diff against working tree
            result = _run_git(
                ["git", *GIT_RAW_PATHS, "diff", *_DIFF_FLAGS, diff_base, "--", *pathspecs],
                target,
            )
            if result is None:
                return None
            if result.returncode != 0:
                # Both the three-dot and two-dot diffs failed — almost always
                # a bad/unknown --diff-base ref. Don't silently parse empty
                # stdout as "0 changed files" (which would let a diff-mode CI
                # run pass green having scanned nothing). Warn loudly.
                print(
                    f"WARN: git diff against base {diff_base!r} failed "
                    f"(exit {result.returncode}). Check the --diff-base ref "
                    f"(in CI, fetch it: actions/checkout `fetch-depth: 0`).",
                    file=sys.stderr,
                )
                return None
        # Also include untracked files
        untracked = _run_git(
            ["git", *GIT_RAW_PATHS, "ls-files", "-z", "--others", "--exclude-standard",
             "--full-name", "--", *pathspecs],
            target,
        )
        if untracked is None or untracked.returncode != 0:
            print(f"WARN: cannot list untracked files{_git_err(untracked)}", file=sys.stderr)
            return None

        git_root = root

        # Both lists are relative to the repo root (`git diff` always,
        # `ls-files` with `--full-name`), whatever folder `target` is.
        changed = {
            _changed_path(git_root / name)
            for name in split_git_paths(result.stdout)
        }
        # An untracked folder is a git checkout inside the work tree. In
        # `.terraform` that's a downloaded module, not a change.
        changed |= {
            _changed_path(git_root / name)
            for name in split_git_paths(untracked.stdout)
            if not (".terraform" in Path(name).parts and (git_root / name).is_dir())
        }
        # A `.terraform` file counts only in a folder the scan reads: one
        # no module calls must not widen the scan to what it calls.
        used = {fp.resolve().parent for fp in tf_files}
        inputs = {
            fp for fp in changed
            if (_is_tf(fp) or _is_tfvars(fp))
            and (".terraform" not in fp.parts or fp.parent in used)
        }
        others = {fp for fp in changed if not _is_tf(fp) and fp.is_file()}
        files = {fp for fp in inputs if fp.exists() and _is_tf(fp)}
        base = files | _module_siblings(inputs)
        if not base:
            return others
        return _with_local_children(base) | _with_local_callers(base, tf_files, ignored) | others
    except _CannotNarrow as e:
        print(f"WARN: cannot narrow the diff: {e}", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("WARN: git not found", file=sys.stderr)
        return None


class GitRefReader:
    """Read files as they are at a git ref (``--inline-ignores-from``).

    The ref is resolved to a commit once; :meth:`read` then returns a
    file's text at that commit, or ``None`` when the file isn't there.
    ``error`` is set (and every read returns ``None``) when the ref can't
    be read at all: git missing or hung, not a work tree, an unknown ref,
    or git refusing the repository (``safe.directory``). Callers must
    treat that as "nothing at the ref is known", i.e. fail closed.
    """

    def __init__(self, ref: str, target: Path) -> None:
        self.ref = ref
        self.error: str | None = None
        self._root: Path | None = None
        self._sha = ""
        cwd = target if target.is_dir() else target.parent
        # A ref that looks like an option would be read as one by git.
        if not ref or ref.startswith("-"):
            self.error = f"invalid ref {ref!r}"
            return
        root, err = verified_work_tree(cwd)
        if root is None:
            self.error = err
            return
        try:
            # A full ref name must exist as written: rev-parse would try
            # `refs/tags/<ref>` and others too, and tags can come from a PR.
            if ref.startswith("refs/"):
                exact = _run_git(["git", "show-ref", "--verify", "--quiet", ref], cwd)
                if exact is None or exact.returncode != 0:
                    self.error = "unknown ref" + _git_err(exact)
                    return
            elif not _SHA_RE.fullmatch(ref):
                self.error = "not a full ref name (refs/...) or commit SHA"
                return
            sha = _run_git(
                ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
                cwd, text=True,
            )
            if sha is None or sha.returncode != 0 or not sha.stdout.strip():
                self.error = "unknown ref" + _git_err(sha)
                return
        except OSError as e:  # git not installed
            self.error = f"git not available ({e})"
            return
        self._root = root
        self._sha = sha.stdout.strip()

    def read(self, path: Path) -> str | None:
        """``path``'s text at the ref (line endings normalised to LF), or
        ``None`` if it doesn't exist there or is outside the work tree."""
        if self.error or self._root is None:
            return None
        try:
            rel = Path(path).resolve().relative_to(self._root).as_posix()
        except ValueError:
            return None
        try:
            res = _run_git(["git", "cat-file", "blob", f"{self._sha}:{rel}"], self._root)
        except OSError:
            return None
        if res is None or res.returncode != 0:
            return None
        text = res.stdout.decode("utf-8", "replace")
        return text.replace("\r\n", "\n").replace("\r", "\n")


def _git_err(res: subprocess.CompletedProcess | None) -> str:
    """`: <first stderr line>` of a failed git call, or `` (timed out)``."""
    if res is None:
        return " (git timed out)"
    err = res.stderr if isinstance(res.stderr, str) else (res.stderr or b"").decode("utf-8", "replace")
    first = err.strip().splitlines()[0] if err.strip() else ""
    return f": {first}" if first else ""
