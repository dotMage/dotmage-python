#!/usr/bin/env bash
set -euo pipefail

echo "Running tests with coverage (gate: 95%)..."
poetry run pytest
