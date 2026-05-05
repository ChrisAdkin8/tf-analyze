#!/usr/bin/env bash
# install.sh — wire this repo into ~/.claude/skills/tf-analyze.
#
# Usage:
#   ./install.sh                # symlink into the default skills dir
#   ./install.sh --copy         # hard-copy instead (snapshot semantics)
#   ./install.sh --force        # overwrite an existing install/symlink
#   ./install.sh --uninstall    # remove the symlink/copy
#   SKILLS_DIR=/path ./install.sh  # override target dir
#
# Default target is $HOME/.claude/skills/tf-analyze. The script never
# touches anything outside the skills dir; safe to re-run.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="${SKILLS_DIR:-$HOME/.claude/skills}"
TARGET="$SKILLS_DIR/tf-analyze"

MODE=symlink
FORCE=0
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --copy) MODE=copy ;;
    --force) FORCE=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --help|-h)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "ERROR: unknown flag $1" >&2
      exit 2
      ;;
  esac
  shift
done

# --- uninstall path ----------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
  if [ -L "$TARGET" ]; then
    echo "removing symlink $TARGET"
    rm "$TARGET"
  elif [ -d "$TARGET" ]; then
    echo "removing directory $TARGET"
    rm -rf "$TARGET"
  else
    echo "$TARGET does not exist; nothing to do"
  fi
  exit 0
fi

# --- pre-flight checks -------------------------------------------------
if [ ! -f "$REPO_DIR/SKILL.md" ]; then
  echo "ERROR: $REPO_DIR/SKILL.md not found — am I in the wrong dir?" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "WARN: python3 not on PATH — the skill won't run until you install Python 3.10+" >&2
fi
mkdir -p "$SKILLS_DIR"

# --- handle pre-existing install --------------------------------------
if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
  if [ "$FORCE" -eq 0 ]; then
    echo "ERROR: $TARGET already exists. Re-run with --force to replace." >&2
    if [ -L "$TARGET" ]; then
      echo "       (current symlink target: $(readlink "$TARGET"))" >&2
    fi
    exit 1
  fi
  BACKUP="$TARGET.preinstall.$(date +%s)"
  echo "moving existing $TARGET -> $BACKUP"
  mv "$TARGET" "$BACKUP"
fi

# --- install ----------------------------------------------------------
case "$MODE" in
  symlink)
    ln -s "$REPO_DIR" "$TARGET"
    echo "installed: $TARGET -> $REPO_DIR (symlink)"
    ;;
  copy)
    cp -R "$REPO_DIR" "$TARGET"
    # Strip git history + caches from the copy so it's a clean snapshot.
    rm -rf "$TARGET/.git" "$TARGET/scripts/__pycache__" 2>/dev/null || true
    echo "installed: $TARGET (copy of $REPO_DIR)"
    echo "NOTE: copy mode is a snapshot. Re-run after pulling repo updates."
    ;;
esac

# --- post-install smoke test ------------------------------------------
if command -v python3 >/dev/null 2>&1; then
  if python3 "$TARGET/scripts/self_test.py" >/dev/null 2>&1; then
    echo "self_test.py passed"
  else
    echo "WARN: self_test.py failed — investigate with:" >&2
    echo "      python3 $TARGET/scripts/self_test.py" >&2
  fi
fi

echo
echo "Next steps:"
echo "  - In Claude Code, run: /tf-analyze"
echo "  - Discover rules:      python3 $TARGET/scripts/detect.py --list-rules"
echo "  - Try the demo corpus: python3 $TARGET/scripts/detect.py --target $REPO_DIR/examples/terragoat"
