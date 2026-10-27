# Architecture

## Package layout

```
sarc/
  cmd/sarc/        CLI entry point (cobra commands, flag parsing, logger init)
  crypto/          Pure crypto primitives — no I/O, no archive concepts
  archive/         Wire format types, metadata sealing, frame builder, archive writer
  io/              File I/O orchestration — streaming archiver, concurrent archiver, extractor
  storage/         Archive objects in local and cloud stores: Backend interface, scheme
                   registry, resumable readers; backends in storage/{local,s3,gcs,azblob}
  tests/           Integration and security tests
  benchmarks/      Performance benchmarks
  scripts/         Developer tooling
```

Dependency direction: `cmd` -> `io` -> `archive` -> `crypto`. No layer imports above itself.
`storage` imports none of them and only `cmd` imports it: the archive code sees an
`io.Writer`, `io.Reader`, or `io.ReaderAt`, wherever the bytes live.

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
  metadata_ciphertext   AES-256-GCM sealed: encrypted_filename | size_bucket | ts_hash | perms | codec (v2+) |
                        attributes_len(4) | attributes (v2+, see File attributes)
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

[PACK ENTRY]            entry_type=0x03, incremental archives only (see Incremental archives)
[INDEX ENTRY]           entry_type=0x04, incremental archives only
[CHECKPOINT]            entry_type=0x05, incremental archives only, unencrypted
[DIRECTORY ENTRY]       entry_type=0x06, one-pass version 2 archives (see Entry directory)
[DIRECTORY LOCATOR]     entry_type=0x07, unencrypted: magic "SARCDLC1"(8) directory_offset(8)

[END MARKER]            entry_type=0x00(1), version 2+ only

[ARCHIVE FOOTER]
  archive_hmac(32)      SHA-256 of all bytes preceding the footer, end marker included
  reserved(32)

[SIGNATURE BLOCK]       optional, after the footer (see Signatures)
  signature             SSH signature (PROTOCOL.sshsig) over archive_hmac
  signature_len(4)
  magic(8)              "SARCSIG1"
```

The reader loops on `entry_type`: `0x01` starts a file entry and, in version 2, `0x02`
starts a solid group, `0x06` and `0x07` (the directory and its locator) are skipped, and
`0x00` ends the entry list. Any other byte, or EOF before the end marker, is a fatal error.
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
recipient_block            := count(2) | stanza*
stanza                     := type(1) | body_len(4) | body
password (0x01)            := iterations(4) | salt(32) | nonce(12) | AES-256-GCM(kek, cek)(48)
                              kek = PBKDF2-SHA256(password, salt, iterations), iterations >= 100_000
age (0x02)                 := a standard age file whose payload is the CEK
key file (0x03)            := salt(32) | nonce(12) | AES-256-GCM(kek, cek)(48)
                              kek = HKDF-SHA256(ikm = key_file, salt, "sarc key file recipient")
key file + password (0x04) := iterations(4) | salt(32) | nonce(12) | AES-256-GCM(kek, cek)(48)
                              kek = HKDF-SHA256(ikm = PBKDF2-SHA256(password, salt, iterations) || key_file,
                                                salt, "sarc key file and password recipient")
```

Each wrap uses its HKDF info string (or "sarc password recipient") as the GCM additional
data, so a stanza cannot be reinterpreted as another type.

- Public-key recipients use age: the CEK is age-encrypted to every recipient, so keys from
  `age-keygen` (or `sarc keygen`) work unchanged, and any identity matching one recipient
  recovers the CEK. Supported: X25519 (`age1...`), post-quantum hybrid (`age1pq1...`),
  tagged hardware keys (`age1tag1...`), SSH ed25519 and RSA, and plugin recipients
  (`age1<name>1...`, served by `age-plugin-<name>` from PATH, for example YubiKey, FIDO2,
  TPM, or Secure Enclave). age X25519 stanzas contain only an ephemeral share, so the
  archive does not reveal those recipients; SSH and most hardware stanzas include a short
  key fingerprint.
- Key files are high-entropy, so their wrap uses HKDF instead of a slow KDF and costs
  microseconds. A key file is any file of 32 bytes to 1 MiB, used verbatim. In the
  combined stanza the password is still stretched with PBKDF2 (in case the key file is
  stolen) and runs once per stanza however many key files are tried. The CLI binds
  `--password` to every `--key` when both are given, so the password alone no longer
  opens the archive.
- Passwords are separate stanzas (age's own scrypt stanza must be the only one in a file).
  The iteration count is stored so it can be raised later; readers reject counts outside
  100k-10M before deriving anything. At most 8 password stanzas, 8 key file stanzas of
  each kind, and one age stanza.
- What is public: the number and kind of stanzas, whether there are age recipients, and
  how many (one age stanza line each). Salts, nonces, and ephemeral shares are fresh per
  archive, so two archives for the same people share no header bytes.
- The extractor tries each stanza only with the credentials it needs (password, key
  files, both, or identities), then confirms the CEK by opening `file_count_encrypted`
  with `header_key`, all before parsing any entry. No match fails with `AUTH_FAILED`,
  names the credential kinds the archive accepts, and writes nothing. An identity that
  fails rather than mismatches (wrong SSH passphrase, missing plugin, cancelled touch) is
  reported as such, after every other stanza has been tried.

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
record := name_len(2) | name | attributes_len(4) | attributes | data_len(8) | data
```

- Grouping: candidates are ordered by extension (similar content shares the compression
  window) and packed until the stream would exceed 8 MiB. A lone candidate is stored as a
  normal file entry. Larger files are always normal entries.
- The whole stream is compressed as one zstd frame (window 8 MiB, the group maximum), the
  result is split into data blocks, and each block is sealed like any other. The codec
  in the sealed metadata applies to the whole stream.
- The trailer HMAC and size cover the uncompressed stream and are verified before any
  member is written. Decoding is bounded at 8 MiB, and member names must be safe
  relative paths (see Directories); any violation rejects the group.
- `sarc list` decrypts solid groups in memory to read member records; each member is
  reported with its group's compression ratio.
- Memory: the archiver holds at most one stream and payload (8 MiB each) per worker. The
  best-compression tier is limited to two concurrent zstd encoders (each holds 35-50 MB),
  and auto mode probes with a separate fastest-level encoder.

## Directories

Archive arguments that are directories are walked in lexical order. A file is stored
under its path relative to the argument's parent, slash-separated (`data/` stores
`data/sub/a.txt`; `.` stores paths relative to itself); a file argument keeps its base
name. Directories are entries too, so empty ones are kept. Inside directories,
symlinks are stored as links (a symlinked directory argument is followed), and a
second path to a file already listed (same device and inode) is stored as a hard link
to it. Devices, sockets, and pipes are skipped and reported.

Stored names must be relative paths whose elements are non-empty and not `.` or `..`,
with no NUL or backslash (`archive.ValidEntryName`). The extractor also requires
`filepath.IsLocal` on the OS form of the name, creates parent directories, and refuses
any other name for that entry only, so no archive can write outside the output
directory.

## File attributes

Version 2 metadata, solid records, and incremental index entries carry the same
attribute encoding (`archive.Attributes`):

```
attributes := kind(1) | mode(4) | mtime_ns(8) | flags(1) | [uid(4) gid(4)] |
              target_len(2) | target | xattr_count(2) | (name_len(1) | name | value_len(4) | value)*
```

- `kind` is regular, directory, symlink, or hard link. Directories and links are file
  entries with no data blocks, written after every file, so a hard link's target is
  always extracted first. A symlink's target is stored as is; a hard link's target is
  the stored name of the entry it links to and must be a safe name.
- `mode` holds the permission bits and setuid (0o4000), setgid (0o2000), and sticky
  (0o1000). `mtime_ns` is the exact modification time; it is encrypted like the name.
- `uid`/`gid` are present only with `--preserve-owner`. Extended attributes include
  macOS resource forks (`com.apple.ResourceFork`) and Linux POSIX ACLs
  (`system.posix_acl_*`); a file's set is bounded at 1 MiB and larger sets are not
  stored, with a warning. macOS ACLs, which are not extended attributes, are not kept.

Extraction (`io/output_tree.go`) opens an `os.Root` on the output directory and
performs every write, rename, symlink, hard link, chmod, chown, and chtimes through it,
so nothing resolves outside the directory, whatever links the archive or the directory
already contains. For each file it sets extended attributes, then the owner (only with
`--preserve-owner`), then the mode (setuid, setgid, and sticky only with
`--preserve-owner`, since chown clears them and they are only safe with the original
owner), renames it into place, and sets its time. Directory attributes are applied
deepest first after every entry, so read-only directories and directory times survive
their contents being written. Failures that lose no data (an attribute a filesystem
refuses, owners without root) are warnings, each general one printed once.

## Incremental archives

`--incremental` creates an archive whose header has `HeaderFlagIncremental` set in its
first reserved byte, or appends a session to one. The archive grows by sessions and
ends with a checkpoint:

```
header | (pack* index)+ | checkpoint | end marker | footer
```

- Chunking: files are split with FastCDC (normalized, min 256 KiB, average 1 MiB, max
  4 MiB) over a gear table derived from the CEK (`HKDF(cek, "sarc chunker gear table")`),
  so cut points, and the chunk sizes they produce, differ between archives for the same
  content. A one-byte edit changes the chunks around it and no others.
- Chunk IDs are `HMAC-SHA256(HKDF(cek, "sarc chunk id key"), chunk)`. A chunk whose ID
  the archive already holds is referenced, not stored again, within and across sessions.
- Packs: new chunks, zstd-compressed when the file's codec is zstd and that is smaller,
  are concatenated into pack entries (at most 64 MiB of plaintext each). A pack uses the
  file-entry framing with random block sizes and padding, so chunk boundaries are
  invisible; its trailer HMAC covers the pack plaintext.
- Session index: one sealed index entry per session lists its packs (archive offsets), its
  new chunks (ID, pack, offset, stored and raw sizes, codec), the new or changed entries
  (name, attributes, size, chunk numbers), and the names deleted since the previous
  session, plus the offset of the previous index. An entry changes when its kind, size,
  mode, time, link target, owner, or extended attributes do. Chunks are numbered globally
  in the order sessions add them.
- Checkpoint: the newest index offset and the marshaled SHA-256 state of every byte
  before the checkpoint, so an update extends the footer checksum without rereading the
  archive. It is not trusted for security: the indexes are authenticated.
- An update reads the checkpoint, walks the index chain back to session 1, applies the
  sessions in order, and compares the inputs: a file with the same size, modification
  time, and mode is not read. New and changed files are chunked; missing files become
  deletions, except under a directory that could not be read. It then writes over the old
  tail (packs, index, new tail), syncs, and reseals the header's session count in place.
  A run with no change writes nothing. A failed write restores the old tail.
- Rollback: the sealed session count (authenticated by the header key) must not exceed
  the newest session found, so cutting off newest sessions and rewriting the unkeyed tail
  is detected. The footer checksum of an incremental archive hashes that count as zeros
  (`archive.ArchiveChecksum`), since updates rewrite it.
- Crash safety: a new archive is written to a temporary file and renamed into place. An
  interrupted update leaves the old sessions intact and the header count unchanged (it is
  rewritten last); readers that find a damaged tail scan forward for the last index that
  verifies completely, and the next update repairs the tail.
- Restore needs random access (`WithRandomAccess`; the CLI provides it for files and
  redirected stdin). Each pack holding a needed chunk is read once, in archive order;
  every chunk is checked against its keyed ID and size before it is written to each
  position that uses it in a temporary file, and a file is renamed into place only when
  all of its chunks are written.
- Limits: indexes are bounded at 256 MiB, chunk and pack sizes are checked when an index
  is parsed, and a file's chunks must add up to its recorded size.

## Split archives

`--split SIZE` cuts the archive stream into volume files `<output>.001`, `.002`, ... of
at most SIZE bytes each:

```
volume := header(40) | payload | checksum(32)
header := "SARCVOL1" | archive_id(16) | index(4) | flags(1) | reserved(3) | payload_len(8)
checksum := SHA-256(payload || header)
```

- Concatenating the payloads in order gives back the single-file archive exactly, so the
  archive format, the readers, and signatures are unchanged; splitting adds 72 bytes per
  volume. `archive_id` is random per archive; the last volume sets flag `0x01`.
- Reading a split archive (named by any volume or the base name) first checks every
  volume's header and size: present, same archive ID, numbered in sequence, length as
  declared, up to the volume marked last. Each volume's checksum is verified as it is
  read. Failures are `io.VolumeError` values naming the volume and file, so a missing,
  truncated, corrupted, reordered, or foreign volume is identified.
- Volumes concatenated into one stream (`cat backup.sarc.* | sarc extract -a -`) are
  recognised by the volume magic and joined the same way.
- The writer creates volumes as data arrives and rewrites the last header with its
  length and flag on close. Stale volumes numbered after the last one, left by an earlier
  and larger archive of the same name, are removed if they start with the volume magic.
- The checksum, like the footer, detects corruption; authenticity still comes from the
  archive's keys. Split output needs files, so it cannot go to stdout, and incremental
  archives (which need one random-access file) cannot be split.

## Signatures

An archive can carry one SSH signature (OpenSSH's PROTOCOL.sshsig format) after its
footer. It signs the 32-byte footer checksum, which commits to every byte before the
footer, so signing and verifying never need the password, and re-signing after an
incremental update costs nothing beyond the update.

- Signed data: `"SSHSIG" | namespace "sarc-archive" | reserved "" | "sha512" |
  SHA-512(checksum)`, as ssh-keygen signs it. Keys: Ed25519, ECDSA (P-256/384/521), and
  RSA of at least 2048 bits signing with rsa-sha2-512; security-key (sk-) signatures can
  be verified. SHA-1 RSA signatures are refused.
- The block is outside the archive proper: readers stop at the end marker, so extraction
  (streaming too) ignores it. An unsigned archive ends with the footer's zero reserved
  bytes, which never match the trailer magic.
- `verify` streams the archive holding back its last 16 KiB + 76 bytes, recomputes the
  checksum, and verifies the signature against the recomputed value, not the stored
  footer. With `--signer` it requires the signature to be valid and by one of the given
  keys (`.pub`, authorized_keys, allowed_signers, or PEM public key files).
- `sign` recomputes the checksum first and refuses a corrupted archive, then appends the
  block, replacing any existing one, without rewriting the archive.
- Incremental archives: a run that changes the archive re-signs with `--sign`, or removes
  the old signature (which no longer matches) and reports it. A run with no change keeps
  a signature that still holds; a failed update restores it with the old tail.
- Checking without sarc: take `signature_len` from the last 12 bytes, the signature
  before them, and the checksum from the first 32 bytes of the footer (64 bytes before
  the signature); armor the signature as `-----BEGIN SSH SIGNATURE-----` base64 and run
  `ssh-keygen -Y verify -n sarc-archive -f allowed_signers -I <id> -s sig < checksum`.

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
| Metadata | Filename, permissions, times, links, owner, and extended attributes encrypted; size bucketed |

## Concurrency model

`ConcurrentArchiver` encrypts files in parallel with bounded memory:

```
dispatcher: sends jobs to workers in order, holding at most workers+2 results in flight
N workers:  encrypt a small file (< 4 MiB) or a solid group in memory -> per-job result channel
writer:     walks jobs in order; writes each result as soon as it is ready, or streams a
            large file (>= 4 MiB) itself with block-level parallelism
```

Entries are written in submission order regardless of which worker finishes first, and
memory is bounded by the window, not by the number or size of files.

## Entry directory

A version 2 archive written in one pass (not incremental) ends its entries with a
directory, then a locator, just before the end marker:

```
header | entries | directory entry | locator | end marker | footer | [signature]
```

The directory entry uses the file-entry framing (own salt, key, padding, data blocks, and
trailer HMAC), so it is encrypted and padded like any file and leaks nothing new. Its
plaintext is `"SARCDIR1"` followed by one record per listed file: entry offset, name,
flags (solid), size bucket, codec, attributes, plaintext size, and stored size (a solid
member's proportional share), the same fields a scanning `list` reports. Both sit before
the footer, so the footer checksum and any signature cover them.

The locator sits at a fixed distance from the end of the archive proper, so a reader with
random access (a regular file, or a storage object through ranged reads) lists the
archive by reading the header, the locator, and the directory, without reading any data
block. A listed entry offset must lie between the header and the directory. The writer
builds the directory as it writes entries and stops at 16 MiB of plaintext (roughly
150,000 files) to keep memory bounded; such an archive has no directory, and `list` falls
back to scanning, as it does for pipes. A damaged directory or locator fails `list` with
`INTEGRITY_FAIL` rather than silently falling back.

## Cloud storage

`cmd` maps archive URLs to backends through a `storage.Registry` (`file`, `s3`, `gs`,
`azblob`); adding a store means implementing `storage.Backend` and registering a scheme.

- Writing: `Backend.Create` returns a writer whose object appears only on `Close`. S3 uses
  a multipart upload (parts of 16 MiB doubling every 1000 parts to 256 MiB, four in
  flight); Azure uploads 16 MiB blocks and commits the block list on close; GCS uses a
  resumable upload; `file://` writes a hidden temporary file and renames it. Any failure,
  and the first Ctrl-C or SIGTERM, aborts the upload, so no partial archive is left.
- Reading: `Backend.Open` pins the object's version (ETag or generation). `extract` and
  `verify` stream it as one request that is reopened at the current offset if the
  connection breaks; `list` and incremental restores use ranged reads. A read of an object
  replaced after it was opened fails instead of mixing versions.
- `--split`, `--incremental`, and `sarc sign` rewrite local files in place, so they reject
  storage URLs.

## Streaming

The format is strictly sequential: the writer only appends (the footer checksum is a
running hash), and the reader never seeks. So archives can be written to and read from
pipes (`--output -`, `--archive -`) with no format change and no temporary archive file.

- Extraction decrypts each file entry block by block into a hidden temporary file in the
  output directory (`.sarc-extract-*`, mode 0600) while computing the plaintext HMAC.
  Only after the trailer verifies is it renamed to its final name; on any failure it is
  deleted. Unverified plaintext never appears under the final name, and memory stays
  constant for any file size. Solid groups (at most 8 MiB) are verified in memory.
- `sarc verify` hashes the stream once, holding back the 64-byte footer, so it also works
  on stdin.
- A truncated stream fails with `TRUNCATED` at the missing end marker; each block, entry,
  and the header remain authenticated, so streaming loses no protection. The footer is an
  unkeyed SHA-256 checksum in every mode: it detects corruption, not tampering.

## Security boundaries

- All `crypto/rand` calls: nonce generation, salt generation, padding generation
- GCM tag is verified by `cipher.AEAD.Open` before any plaintext is returned
- Plaintext HMAC is verified in constant time after decryption, before an extracted file is renamed to its final name
- Error messages never include key material, decrypted filenames, or internal stack traces
- Archive signatures are verified against the recomputed checksum, and only Ed25519, ECDSA, and RSA (SHA-512, 2048+ bits) are accepted
