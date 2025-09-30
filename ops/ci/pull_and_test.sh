#!/usr/bin/env bash
set -euo pipefail

# Small lock to prevent concurrent runs
LOCKFILE=/tmp/pull_and_test.lock
exec 9>$LOCKFILE
flock -n 9 || exit 0

REPO_DIR=${REPO_DIR:-/home/nsatech/Element.}
DEPLOY_KEY=${DEPLOY_KEY:-$HOME/.ssh/github}

# Ensure rustup/cargo from the user's home is available when run under systemd
# (systemd services may not load the user's shell profile). Prefer the
# rustup-provided env file if present, and always prepend $HOME/.cargo/bin to PATH.
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck source=/dev/null
    . "$HOME/.cargo/env" || true
fi
export PATH="$HOME/.cargo/bin:$PATH"

echo "[ci] Updating repo in $REPO_DIR"
cd "$REPO_DIR"

export GIT_SSH_COMMAND="ssh -i $DEPLOY_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"

git fetch --all --prune
git reset --hard origin/main

echo "[ci] Running quick smoke tests"
# Run a fast smoke test; adjust to your project's test command
if command -v cargo >/dev/null 2>&1; then
    cargo test --lib --quiet || { echo "[ci] cargo tests failed"; exit 1; }
else
    echo "[ci] cargo not present; skipping Rust tests"
fi

echo "[ci] Success"
