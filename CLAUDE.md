# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build ./...
go build -o ./sarc ./cmd/sarc

# Test (all packages, with race detector)
go test -race -count=1 ./...

# Run a single test
go test -race -run TestName ./package/...
# Example: go test -race -run TestMetadataSealOpenRoundtrip ./archive/...

# Benchmarks (smoke run, no timing)
go test -run='^$' -bench=. -benchtime=1x ./benchmarks/...

# Full benchmark with output
go test -bench=. -benchmem ./benchmarks/...

# Lint
gofmt -l .
go vet ./...

# Add copyright headers to new Go files
./scripts/add-copyright.sh                    # all tracked .go files
./scripts/add-copyright.sh path/to/file.go   # specific file
```

## Architecture

Strict unidirectional dependency: `cmd` -> `io` -> `archive` -> `crypto`. No layer imports above itself.

```
cmd/sarc/     CLI (cobra). Thin — parses flags, calls io layer, handles progress display.
io/           Orchestration. StreamingArchiver, ConcurrentArchiver, SafeExtractor.
archive/      Wire format. ArchiveWriter, FrameBuilder, MetadataManager. No I/O.
crypto/       Pure primitives. EncryptionManager, KeyDeriver, padding, HMAC. No I/O.
tests/        Integration and security tests (CLI roundtrip, dedup resistance, tamper detection).
benchmarks/   Go benchmarks comparing sarc vs stdlib operations.
examples/     Standalone Go programs showing archive/extract API usage.
```

### On-disk format

Each file entry in the `.sarc` container has its own AES-256 key. Format version 2 (current) stretches the password once per archive, then expands per-file keys with HKDF:
`master_key = PBKDF2(password, archive_salt, 100_000 iterations, SHA-256)`, `file_key = HKDF-SHA256-Expand(master_key, "sarc file key" || entry_salt)`.
Version 1 archives (one PBKDF2 per file entry) remain extractable; `archive.KeySchedule` selects the derivation from the header version. `tests/testdata/v1_multi.sarc` is the v1 compatibility fixture.

Data is split into variable-length blocks (~64 KB ± 8 KB), each with a unique 12-byte `crypto/rand` nonce. A sealed HMAC-SHA256 of the plaintext is stored encrypted at the end of each file entry and verified with `crypto/subtle.ConstantTimeCompare` after decryption — before writing any output to disk.

### Anti-deduplication

The core security property: the same file archived twice must produce completely different ciphertext. This is enforced by five independent layers — unique 32-byte salt per file entry, random header/trailer padding from `crypto/rand`, variable chunk sizes, unique nonce per block, and encrypted metadata (filename, size bucket, day-truncated timestamp hash). None of these layers can be disabled or skipped.

### Concurrency model

`ConcurrentArchiver` (in `io/concurrent.go`) encrypts files in parallel using a goroutine pool. A collector goroutine assembles results in submission order before the writer flushes them, preserving deterministic archive layout regardless of which worker finishes first. The streaming archiver (`io/streaming.go`) maintains <200 MB memory by processing one 64 KB chunk at a time.

## Project Conventions

**Copyright header** — every Go source file must start with:
```go
// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.
```
Run `./scripts/add-copyright.sh` on any new file before committing. The CI lint job fails without it.

**Comments** — GoDoc only: one-line summary starting with the identifier name, then minimal contract notes if non-obvious. No conversational prose ("its sole purpose is", "so the receiver can").

**Git** — default branch is `master`. Branch naming: `feat/`, `fix/`, `hotfix/` prefixes (these drive the PR auto-labeler). No `Co-Authored-By` trailers in commits. No em dashes in any text.

**Error messages** — must never include key material, decrypted filenames, or internal stack traces. The `io/errors.go` `ArchiveError` type carries `isFatal` to distinguish recoverable from fatal failures.

## Release Flow

Pushing a `v*` tag (or running the Release workflow manually) triggers:
1. `release.yml` — creates the GitHub release with auto-generated notes grouped by PR label, then opens a PR to prepend the notes to `CHANGELOG.md`.
2. `build.yml` — fires on `workflow_run` after release completes, runs the quality gate (tests + gofmt + go vet + license headers), then GoReleaser builds multi-platform binaries (`linux/darwin/windows`, `amd64/arm64`) and uploads them to the existing release in append mode.
3. Docker image published to `ghcr.io/iamvirul/sarc` with semver tags + `latest`.

`.goreleaser.yml` is set to `release.mode: append` — it never creates the release itself, only uploads artifacts to the one `release.yml` already created.
