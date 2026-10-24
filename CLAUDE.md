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

Each file entry in the `.sarc` container has its own AES-256 key. Format version 2 (current) uses a random per-archive content key (CEK) and expands per-file keys with HKDF:
`file_key = HKDF-SHA256-Expand(cek, "sarc file key" || entry_salt)`. The header's recipient block (`archive/recipients.go`) stores the CEK wrapped per password (PBKDF2 + AES-256-GCM), per key file (HKDF, `crypto/keyfile.go`), per key file + password pair (both required), and once for all age recipients (`filippo.io/age`: X25519, SSH, plugins for hardware tokens); any one stanza unlocks the archive. CLI parsing of keys, identities, and plugin prompts lives in `cmd/sarc/credentials.go`, `identities.go`, and `terminal.go`; `tests/testdata/age-plugin-sarctest` is a test-only plugin.
Version 1 archives (one PBKDF2 per file entry) remain extractable; `archive.KeySchedule` selects the derivation from the header version. `tests/testdata/v1_multi.sarc` is the v1 compatibility fixture.

Version 2 can zstd-compress each file before encryption (`archive/codec.go`, policy in `io/compression.go`). The codec is per file, stored in sealed metadata; each block of a zstd entry is an independent frame, so `FrameBuilder` compresses inside its chunk-encrypt methods and the pipelines are codec-agnostic. The HMAC and the trailer's plaintext size cover the original plaintext.

Opt-in solid mode (`--solid`, `io/solid.go`, record format in `archive/solid.go`) packs files up to 1 MiB into solid group entries (`EntryTypeSolid`, up to 8 MiB uncompressed) compressed as one zstd stream. Groups reuse the file-entry framing, so skip/resync logic is shared; extraction verifies the group HMAC before writing any member.

Directory arguments are archived recursively under slash-separated relative names (`io/inputs.go`); `archive.ValidEntryName` and the extractor's `entryOutputPath` keep every entry inside the output directory.

`--incremental` (`io/incremental*.go`, format in `archive/incremental.go`, chunker in `archive/chunker.go`) builds an append-only archive of sessions: FastCDC chunks over a CEK-keyed gear table, named by keyed HMAC and deduplicated, are packed into encrypted pack entries, and each session ends with a sealed index of new chunks, changed files, and deletions. A checkpoint before the footer locates the newest index and carries the checksum state for the next append; the header's sealed count is the session count, rewritten last, so rollbacks are detected (`archive.ArchiveChecksum` masks it in the footer checksum). Restoring needs random access (`WithRandomAccess`).

File attributes (`archive/attributes.go`: kind, mode with setuid/setgid/sticky, mtime, link target, optional uid/gid, xattrs) live in v2 metadata, solid records, and incremental index entries. Directories, symlinks, and hard links are data-free entries written after all files. Extraction goes through `io/output_tree.go`, an `os.Root` on the output directory, so nothing escapes it; owners and special mode bits are restored only with `WithRestoreOwner` (`--preserve-owner`). Platform code: `io/xattr_{unix,linux,darwin,other}.go`, `io/fileinfo_{unix,other}.go`.

`--split SIZE` (`io/volume.go`, format in `archive/volume.go`) cuts the archive stream into volume files `<output>.001`, `.002`, ... each framed by a header (random archive ID, index, last flag, payload length) and a SHA-256 checksum. Joining the payloads gives back the single-file archive, so readers are unchanged; the CLI detects volumes from any volume name, the base name, or stdin, and `io.VolumeError` names a missing or damaged volume.

Optional signatures (`archive --sign`, `sarc sign`, `verify --signer`) are OpenSSH SSHSIG signatures (`crypto/signature.go`, namespace `sarc-archive`) over the footer checksum, stored in a block after the footer (`archive/signature.go`, `io/signature.go`); readers stop at the end marker, so extraction ignores it. Incremental updates re-sign or drop the stale signature.

Data is split into variable-length blocks (~64 KB ± 8 KB), each with a unique 12-byte `crypto/rand` nonce. A sealed HMAC-SHA256 of the plaintext is stored encrypted at the end of each file entry. Extraction streams each file into a hidden temp file (`io/verified_file.go`) while computing the HMAC, and renames it into place only after a constant-time match, so memory is constant and unverified data never appears under the final name. The footer is an unkeyed SHA-256 checksum (corruption detection only).

### Anti-deduplication

The core security property: the same file archived twice must produce completely different ciphertext. This is enforced by five independent layers: unique 32-byte salt per file entry, random header/trailer padding from `crypto/rand`, variable chunk sizes, unique nonce per block, and encrypted metadata (filename, size bucket, and the file attributes). None of these layers can be disabled or skipped.

### Concurrency model

`ConcurrentArchiver` (in `io/concurrent.go`) encrypts small files and solid groups on a goroutine pool and writes results in submission order as they complete, with at most workers+2 results in flight; files of 4 MiB or more are streamed by the writer itself. Memory is bounded regardless of archive size, and `--output -` / `--archive -` stream archives through pipes.

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
