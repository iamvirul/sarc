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
[ARCHIVE HEADER]        magic(4) version(2) salt(32) file_count_encrypted(36) reserved(32)

[FILE ENTRY]  (repeated)
  entry_type(1)         0x01 = file
  entry_salt(32)        unique per file, used for PBKDF2 key derivation
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

[ARCHIVE FOOTER]
  archive_hmac(32)      SHA-256 of all bytes preceding the footer
  reserved(32)
```

## Key derivation

Every file gets its own independent AES-256 key:

```
file_key = PBKDF2(master_password, entry_salt, 100_000, 32, SHA-256)
```

The archive salt in the header is used to derive the master key for sealing the file count:

```
master_key = PBKDF2(master_password, archive_salt, 100_000, 32, SHA-256)
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
