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
- Client-side cryptography core (`dotmage.core.crypto`): Argon2id key derivation, account-key
  generation and wrapping (with a recovery-code path), authenticated blob encryption with a
  versioned envelope and content hashing, and domain-separated sealed keys for team
  invitations — all pinned in `crypto.suite` for interop review.
- Dependency-free `.env` parser/serialiser (`dotmage.dotenv`).
- Full exception hierarchy with server error-code mapping (`dotmage.exceptions`).
- Configuration (`dotmage.settings`, env prefix `DOTMAGE_`), enumerations (`dotmage.enums`),
  and typed API response models plus SDK value objects — diff, drift status, invite payload
  (`dotmage.models`).
- HTTP transport (`dotmage.core.http`): sync and async clients over httpx with a tenacity
  retry policy (transient exceptions + retryable statuses), Bearer injection, transparent
  one-shot token refresh on 401, and error-response mapping.
- Credential stores (`dotmage.core.credentials`): in-memory and file-backed (`0600`).
