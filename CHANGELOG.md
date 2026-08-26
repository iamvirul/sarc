# Changelog

## 1.1.0 - 2026-08-26

<!-- Release notes generated using configuration in .github/release.yml at 1.1.0 -->

## What's Changed
### New Features
* perf: replace crypto/rand hot-path reads with BufferedRand by @iamvirul in https://github.com/iamvirul/sarc/pull/37
* perf: pipeline read+encrypt with write via 2-stage goroutine by @iamvirul in https://github.com/iamvirul/sarc/pull/38
* perf: zero-alloc hot path via combined plaintext+ciphertext pool by @iamvirul in https://github.com/iamvirul/sarc/pull/39
* Parallelise intra-file block encryption and decryption by @iamvirul in https://github.com/iamvirul/sarc/pull/42
* Memory-mapped I/O for files >= 64 MB by @iamvirul in https://github.com/iamvirul/sarc/pull/43
* Pre-allocate output file to reduce fragmentation on large archives by @iamvirul in https://github.com/iamvirul/sarc/pull/45
### Bug Fixes
* Replace broken SLSA workflow with GoReleaser for release binaries by @iamvirul in https://github.com/iamvirul/sarc/pull/13
* Replace broken SLSA workflow with GoReleaser for release binaries by @iamvirul in https://github.com/iamvirul/sarc/pull/14
* Add binary format roundtrip tests and 3D mesh benchmark by @iamvirul in https://github.com/iamvirul/sarc/pull/41
### Security
* perf: increase block size from 64 KB to 256 KB by @iamvirul in https://github.com/iamvirul/sarc/pull/36
* perf: buffer ArchiveWriter output to batch OS write syscalls by @iamvirul in https://github.com/iamvirul/sarc/pull/40
### Documentation
* Add CLAUDE.md for Claude Code guidance by @iamvirul in https://github.com/iamvirul/sarc/pull/35
### Other Changes
* Add regression benchmarks for small-file archive targets by @iamvirul in https://github.com/iamvirul/sarc/pull/44

## New Contributors
* @github-actions[bot] made their first contribution in https://github.com/iamvirul/sarc/pull/12

**Full Changelog**: https://github.com/iamvirul/sarc/compare/1.0.0...1.1.0

---

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

## Security audit

- [x] All nonces generated with crypto/rand
- [x] All file salts unique, 32 bytes from crypto/rand
- [x] PBKDF2 iterations >= 100,000
- [x] GCM tag verified before any plaintext returned
- [x] Plaintext HMAC verified with crypto/subtle.ConstantTimeCompare before writing output
- [x] No plaintext leakage in error messages
- [x] Random padding always included, never skipped
- [x] Variable chunk sizes prevent pattern analysis
- [x] Archive HMAC prevents container-level tampering

**Full Changelog**: https://github.com/iamvirul/sarc/commits/1.0.0

---
