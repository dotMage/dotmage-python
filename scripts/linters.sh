#!/usr/bin/env bash
set -euo pipefail

echo "Linting with Ruff..."
poetry run ruff check . --fix

echo "Checking formatting with Ruff..."
poetry run ruff format --check .

echo "Type-checking with mypy..."
poetry run mypy .
