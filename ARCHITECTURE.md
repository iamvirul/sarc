# Architecture

## Package layout

```
sarc/
  cmd/sarc/        CLI entry point (cobra commands, flag parsing, logger init)
  crypto/          Pure crypto primitives — no I/O, no archive concepts
  archive/         Wire format types, metadata sealing, frame builder, archive writer
  io/              File I/O orchestration — streaming archiver, concurrent archiver, extractor
  tests/           Integration and security tests
  benchmarks/      Performance benchmarks
  scripts/         Developer tooling
```

Dependency direction: `cmd` -> `io` -> `archive` -> `crypto`. No layer imports above itself.

## On-disk format

```
[ARCHIVE HEADER]        magic(4) version(2) archive_salt(32) file_count_encrypted(36) reserved(32)

[FILE ENTRY]  (repeated)
  entry_type(1)         0x01 = file
  entry_salt(32)        unique per file, input to the per-file key derivation
  frame_header(32)      random bytes, no semantic content
  metadata_nonce(12)
  metadata_size(4)
  metadata_ciphertext   AES-256-GCM sealed: encrypted_filename | size_bucket | ts_hash | perms
  interblock_pad_size(4)
  interblock_pad        random(256-1024 bytes)
  [DATA BLOCKS]  (repeated)
    nonce(12)
    size(4)
    ciphertext          AES-256-GCM block, variable length ~64 KB +/- 8 KB
  [SENTINEL]            nonce=0(12) size=0(4), marks end of data blocks
  trailer_pad_size(4)
  trailer_pad           random(256-512 bytes)
  hmac_nonce(12)
  hmac_sealed_size(4)
  hmac_sealed           AES-256-GCM sealed HMAC-SHA256(plaintext), verified after decryption
  entry_checksum(8)     random, used for boundary detection only

[END MARKER]            entry_type=0x00(1), version 2+ only

[ARCHIVE FOOTER]
  archive_hmac(32)      SHA-256 of all bytes preceding the footer, end marker included
  reserved(32)
```

The reader loops on `entry_type`: `0x01` starts a file entry and, in version 2, `0x00`
ends the entry list. Any other byte, or EOF before the end marker, is a fatal error.
Version 1 archives have no end marker, so the reader treats EOF or any byte other than
`0x01` as the end. That heuristic misreads roughly 1 in 256 version 1 archives, whose
footer HMAC happens to start with `0x01`, as having one extra (failing) entry.

## Key derivation

The `version` header field selects the key schedule (`archive.KeySchedule`). New archives
are always written as version 2; the extractor accepts versions 1 and 2.

### Version 2 (current)

The password is stretched once per archive, then every file gets its own AES-256 key
via HKDF-SHA256:

```
master_key = PBKDF2(password, archive_salt, 100_000, 32, SHA-256)       // once per archive
file_key   = HKDF-Expand(master_key, "sarc file key" || entry_salt, 32)  // per file entry
header_key = HKDF-Expand(master_key, "sarc header key", 32)              // seals file count
```

`master_key` is already uniformly random, so HKDF-Extract is skipped (RFC 5869 section 3.3).
The extractor opens `file_count_encrypted` with `header_key` before parsing any entry, so a
wrong password fails immediately with `AUTH_FAILED` and nothing is written to disk.
Each entry still has a unique key because every `entry_salt` is unique, and file keys are
one-way outputs of `master_key`: recovering a file key does not reveal `master_key` or other
file keys. The master key itself is never used directly as an encryption key.

Archiving or extracting N files costs one PBKDF2 run plus N HKDF expansions (microseconds
each), instead of N PBKDF2 runs.

### Version 1 (read-only)

Archives written before v2.0.0 derive each file key with its own PBKDF2 run:

```
file_key   = PBKDF2(password, entry_salt, 100_000, 32, SHA-256)
master_key = PBKDF2(password, archive_salt, 100_000, 32, SHA-256)  // sealed file count
```

## Anti-deduplication layers

| Layer | Mechanism |
|---|---|
| Key | Unique 32-byte salt per file |
| Padding | Random header (1-4 KB) and trailer (512-2048 B) from crypto/rand |
| Chunks | Base 64 KB +/- random(0-8 KB) per block |
| Nonce | 12-byte crypto/rand nonce per block |
| Metadata | Filename encrypted, size bucketed, timestamp day-truncated and hashed |

## Concurrency model

`ConcurrentArchiver` encrypts files in parallel:

```
main goroutine: sends fileJob{index, path} to jobs channel
N workers:      read jobs, encrypt file -> send fileResult{index, entry} to results channel
collector:      reads all results into ordered[index] slice
writer:         flushes ordered slice to archive in submission order
```

Result ordering preserves deterministic archive layout regardless of which worker finishes first.

## Security boundaries

- All `crypto/rand` calls: nonce generation, salt generation, padding generation
- GCM tag is verified by `cipher.AEAD.Open` before any plaintext is returned
- Plaintext HMAC is verified by `crypto/subtle.ConstantTimeCompare` after decryption, before writing output
- Error messages never include key material, decrypted filenames, or internal stack traces
