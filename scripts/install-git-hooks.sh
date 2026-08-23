#!/usr/bin/env sh
# Install this repo's git hooks (commit-msg) into the local clone.
#
# This repo has no npm `prepare` script (Node-only, no package.json), so we
# install the hook by pointing core.hooksPath at .githooks. Idempotent.
#
# Usage: ./scripts/install-git-hooks.sh
set -eu

REPO_ROOT="$(git rev-parse --show-toplevel)"

if [ ! -f "$REPO_ROOT/.githooks/commit-msg" ]; then
    printf '%s\n' "error: $REPO_ROOT/.githooks/commit-msg not found" >&2
    exit 1
fi

chmod +x "$REPO_ROOT/.githooks/commit-msg"
git config core.hooksPath .githooks

printf '%s\n' "git hooks installed: core.hooksPath=$(git config core.hooksPath)"
