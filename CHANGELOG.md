# Changelog

All notable changes to the dotMage Python SDK are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The published version is guarded in CI: a build fails if its version already exists on PyPI,
so every user-visible change must bump the version under `[Unreleased]` in the same change.

## [Unreleased]

### Added
- Project scaffolding: Poetry (PEP 621), Ruff + mypy (strict), pytest with a 95% coverage
  gate, pre-commit, GitHub Actions CI (check-version / lint / test / build / publish), and
  the typed package skeleton (`py.typed`).
