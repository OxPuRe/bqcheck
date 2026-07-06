#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

chmod +x scripts/check_ci.sh scripts/git-hooks/pre-push
git config core.hooksPath scripts/git-hooks

echo "Installed git hooks from scripts/git-hooks"

