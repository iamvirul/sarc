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
[ARCHIVE HEADER]        v2: magic(4) version(2) recipient_block_len(4) recipient_block
                            file_count_encrypted(36) reserved(32)
                        v1: magic(4) version(2) archive_salt(32) file_count_encrypted(36) reserved(32)

[FILE ENTRY]  (repeated)
  entry_type(1)         0x01 = file
  entry_salt(32)        unique per file, input to the per-file key derivation
  frame_header(32)      random bytes, no semantic content
  metadata_nonce(12)
  metadata_size(4)
  metadata_ciphertext   AES-256-GCM sealed: encrypted_filename | size_bucket | ts_hash | perms | codec (v2+)
  interblock_pad_size(4)
  interblock_pad        random(256-1024 bytes)
  [DATA BLOCKS]  (repeated)
    nonce(12)
    size(4)
    ciphertext          AES-256-GCM block over the payload: the plaintext chunk (~256 KB +/- 32 KB)
                        for codec none, or one independent zstd frame of it for codec zstd
  [SENTINEL]            nonce=0(12) size=0(4), marks end of data blocks
  trailer_pad_size(4)
  trailer_pad           random(256-512 bytes)
  hmac_nonce(12)
  hmac_sealed_size(4)
  hmac_sealed           AES-256-GCM sealed HMAC-SHA256(plaintext) | plaintext_size(8, v2+),
                        verified after decryption and decompression
  entry_checksum(8)     random, used for boundary detection only

[SOLID GROUP ENTRY]     entry_type=0x02, version 2+ only; same framing as a file entry,
                        but the plaintext is a record stream (see Solid groups)

[END MARKER]            entry_type=0x00(1), version 2+ only

[ARCHIVE FOOTER]
  archive_hmac(32)      SHA-256 of all bytes preceding the footer, end marker included
  reserved(32)
```

The reader loops on `entry_type`: `0x01` starts a file entry and, in version 2, `0x02`
starts a solid group and `0x00` ends the entry list. Any other byte, or EOF before the end marker, is a fatal error.
Version 1 archives have no end marker, so the reader treats EOF or any byte other than
`0x01` as the end. That heuristic misreads roughly 1 in 256 version 1 archives, whose
footer HMAC happens to start with `0x01`, as having one extra (failing) entry.

## Key derivation

The `version` header field selects the key schedule (`archive.KeySchedule`). New archives
are always written as version 2; the extractor accepts versions 1 and 2.

### Version 2 (current)

Every archive has a random 32-byte content-encryption key (CEK) from `crypto/rand`. Each
file gets its own AES-256 key derived from it with HKDF-SHA256:

```
cek        = random(32)                                           // once per archive
file_key   = HKDF-Expand(cek, "sarc file key" || entry_salt, 32)  // per file entry
header_key = HKDF-Expand(cek, "sarc header key", 32)              // seals file count
```

The CEK is uniformly random, so HKDF-Extract is skipped (RFC 5869 section 3.3). Each entry
has a unique key because every `entry_salt` is unique, and file keys are one-way outputs of
the CEK. The CEK itself is never used directly as an encryption key.

### Recipients

The CEK is never derived from a credential. The header's recipient block holds one
wrapped copy of it per way to open the archive, and any one of them unlocks everything:

```
recipient_block := count(2) | stanza*
stanza          := type(1) | body_len(4) | body
password (0x01) := iterations(4) | salt(32) | nonce(12) | AES-256-GCM(kek, cek)(48)
                   kek = PBKDF2-SHA256(password, salt, iterations), iterations >= 100_000
age (0x02)      := a standard age file whose payload is the CEK
```

- Public-key recipients use age: the CEK is age-encrypted to every `age1...` recipient, so
  keys from `age-keygen` (or `sarc keygen`) work unchanged, and any age identity matching
  one recipient recovers the CEK. age X25519 stanzas contain only an ephemeral share, so
  the archive does not reveal recipient public keys.
- Passwords are separate stanzas (age's own scrypt stanza must be the only one in a file).
  The iteration count is stored so it can be raised later; readers reject counts outside
  100k-10M before deriving anything. At most 8 password stanzas, one age stanza.
- What is public: the number of password stanzas, whether there are age recipients, and
  how many (one age stanza line each). Salts, nonces, and ephemeral shares are fresh per
  archive, so two archives for the same people share no header bytes.
- The extractor tries the password against password stanzas and identities against the
  age stanza, then confirms the CEK by opening `file_count_encrypted` with `header_key`,
  all before parsing any entry. No match fails with `AUTH_FAILED` and writes nothing.

Archiving or extracting costs one PBKDF2 run per password tried plus one HKDF expansion
per file (microseconds each).

### Version 1 (read-only)

Archives written before v2.0.0 derive each file key with its own PBKDF2 run:

```
file_key   = PBKDF2(password, entry_salt, 100_000, 32, SHA-256)
master_key = PBKDF2(password, archive_salt, 100_000, 32, SHA-256)  // sealed file count
```

## Compression

Format version 2 can zstd-compress a file before encryption:

```
plaintext chunk -> [zstd frame, if codec = zstd] -> AES-256-GCM -> data block
```

- The codec is chosen per file and stored in the sealed metadata, so it is encrypted and
  authenticated. Every block of a zstd entry is an independent frame, which keeps the
  parallel encrypt and decrypt pipelines unchanged.
- Modes: `auto` (default) test-compresses the first 64 KB and compresses only if it shrinks
  by at least 5%, skipping known compressed extensions without a probe; `always`; `never`.
- The HMAC covers the original plaintext, and the trailer records its exact size, so the
  extractor verifies the decompressed output, not the compressed payload.
- Decoding is bounded: a block may not decode to more than one maximum chunk (288 KB), and
  data block, metadata, and sealed trailer lengths are checked before allocation.
- `sarc list` reads the stored size from block length prefixes and the original size from
  the trailer, so it never decrypts data blocks.

Version 1 entries have no codec byte and decode as uncompressed.

## Solid groups

With `--solid`, regular files of at most 1 MiB are packed into groups. Each group is one
entry with one salt, one key, one padding set, and one trailer, which amortises the
~2.2 KB of per-entry padding and lets zstd match across files.

```
stream := record*
record := name_len(2) | name | permissions(4) | data_len(8) | data
```

- Grouping: candidates are ordered by extension (similar content shares the compression
  window) and packed until the stream would exceed 8 MiB. A lone candidate is stored as a
  normal file entry. Larger files are always normal entries.
- The whole stream is compressed as one zstd frame (window 8 MiB, the group maximum), the
  result is split into data blocks, and each block is sealed like any other. The codec
  in the sealed metadata applies to the whole stream.
- The trailer HMAC and size cover the uncompressed stream and are verified before any
  member is written. Decoding is bounded at 8 MiB, and member names must be non-empty
  base names without `/` or NUL and not `.` or `..`; any violation rejects the group.
- `sarc list` decrypts solid groups in memory to read member records; each member is
  reported with its group's compression ratio.
- Memory: the archiver holds at most one stream and payload (8 MiB each) per worker. The
  best-compression tier is limited to two concurrent zstd encoders (each holds 35-50 MB),
  and auto mode probes with a separate fastest-level encoder.

## Error recovery

A failure inside one entry (authentication, decompression, integrity) is recoverable: the
extractor skips the rest of that entry using its length prefixes and continues with the
next one. A corrupt length prefix, an unexpected entry type, or truncation loses the
framing, so it is fatal and extraction stops.

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
