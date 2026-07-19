# Changelog

## 1.0.0 - 2026-07-19

<!-- Release notes generated using configuration in .github/release.yml at 1.0.0 -->

## What's Changed
### New Features
* Phase 1: Core crypto package by @iamvirul in https://github.com/iamvirul/sarc/pull/2
* Phase 2: Archive format + copyright headers + script by @iamvirul in https://github.com/iamvirul/sarc/pull/3
* Phase 3: I/O and streaming by @iamvirul in https://github.com/iamvirul/sarc/pull/4
* Phase 4: CLI, tests, CI, and SLSA provenance release workflow by @iamvirul in https://github.com/iamvirul/sarc/pull/5
* Docs, examples, Docker, MIT license, and benchmark workflow by @iamvirul in https://github.com/iamvirul/sarc/pull/6
### Bug Fixes
* Fix benchmark workflow: env context invalid in job name by @iamvirul in https://github.com/iamvirul/sarc/pull/8
* Fix release workflow: use PR for CHANGELOG update to respect branch protection by @iamvirul in https://github.com/iamvirul/sarc/pull/9
* Fix release workflow: request owner review instead of auto-merge for CHANGELOG PR by @iamvirul in https://github.com/iamvirul/sarc/pull/11
### CI / Build
* Initialize SARC project structure by @iamvirul in https://github.com/iamvirul/sarc/pull/1
* Add benchmark workflow: sarc vs zip comparison on every PR by @iamvirul in https://github.com/iamvirul/sarc/pull/7

## New Contributors
* @iamvirul made their first contribution in https://github.com/iamvirul/sarc/pull/1

**Full Changelog**: https://github.com/iamvirul/sarc/commits/1.0.0

---

## v1.0.0 (2026-07-19)

Initial release.

### Features

- AES-256-GCM encryption with per-block random nonces
- PBKDF2-SHA256 key derivation, 100k iterations, unique 32-byte salt per file
- Anti-deduplication: random padding, variable chunk sizes, per-file key isolation
- Metadata protection: encrypted filenames, size buckets, hashed timestamps
- Container-level HMAC-SHA256 for tamper detection without decryption
- Streaming archiver with < 200 MB memory footprint
- Concurrent archiver with configurable worker count (default: NumCPU)
- CLI commands: archive, extract, verify, list
- SLSA level-3 signed release binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64

### Security audit

- [x] All nonces generated with crypto/rand
- [x] All file salts unique, 32 bytes from crypto/rand
- [x] PBKDF2 iterations >= 100,000
- [x] GCM tag verified before any plaintext returned
- [x] Plaintext HMAC verified with crypto/subtle.ConstantTimeCompare before writing output
- [x] No plaintext leakage in error messages
- [x] Random padding always included, never skipped
- [x] Variable chunk sizes prevent pattern analysis
- [x] Archive HMAC prevents container-level tampering
