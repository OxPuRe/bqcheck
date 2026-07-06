#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

export BQCHECK_REAL_MODE="${BQCHECK_REAL_MODE:-false}"
export BQCHECK_REAL_SCAN="${BQCHECK_REAL_SCAN:-false}"

echo "==> Installing dependencies"
uv sync --group dev

echo "==> Ruff lint"
uv run ruff check .

echo "==> Ruff format check"
uv run ruff format --check .

echo "==> Mypy"
uv run python -m mypy src/

echo "==> Pytest with coverage"
uv run python -m pytest --cov --cov-report=xml --cov-report=term
