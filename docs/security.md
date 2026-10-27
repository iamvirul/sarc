# Security model

sarc's core guarantee: archiving the same file twice produces completely different
ciphertext, so an observer cannot tell which archives share content, and stored or
transmitted archives defeat deduplication-based attacks. On top of that, every byte is
authenticated, and nothing about the files is visible without a credential except
coarse sizes.

The on-disk format behind these properties is in [ARCHITECTURE.md](ARCHITECTURE.md).

## Properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM per block |
| Key isolation | Random per-archive content key; a unique HKDF-SHA256 key per file from a unique 32-byte salt |
| Recipients | Content key wrapped once per password (PBKDF2-SHA256, 100k+ iterations, AES-256-GCM), once per key file (HKDF-SHA256, AES-256-GCM), once per key file + password pair (both combined in one HKDF), and once for all public-key recipients (age X25519, SSH, plugins); recipient public keys are not stored |
| Integrity | GCM auth tag per block + HMAC-SHA256 over full plaintext |
| Deduplication resistance | Random padding (1-4 KB header, 512-2048 B trailer), variable chunk sizes (64 KB +/- 8 KB), unique nonce per block |
| Metadata protection | Filename, permissions, modification time, link targets, owner, and extended attributes are inside the encrypted metadata; the visible size is bucketed (not exact) |
| Listing | The entry directory that lets `list` skip file data is encrypted and padded like a file entry |
| Safe extraction | Every write, link, and attribute change goes through an `os.Root` on the output directory, so no entry name, symlink in the archive, or symlink already in the output directory can make extraction write outside it |
| Compression | Optional zstd before encryption, per file; the codec is recorded inside the encrypted metadata |
| Solid groups (`--solid`) | Small files share one entry: one key, one padding set, one HMAC per group of up to 8 MiB |
| Incremental archives (`--incremental`) | Files are split into content-defined chunks (about 1 MiB) whose boundaries depend on a secret derived from the archive key; chunks are named by keyed HMAC, deduplicated within the archive, and packed into encrypted, padded pack entries, so chunk boundaries and identities never appear outside the encryption. The header seals the session count, so cutting off the newest sessions is detected |
| Container checksum | SHA-256 over the archive body in the footer, checked by `sarc verify` without a password. It is not keyed: it detects accidental corruption, not tampering |
| Provenance (`--sign`, `sign`) | Optional SSH signature (Ed25519, ECDSA, or RSA with SHA-512) over the footer checksum, appended after the footer. `verify --signer` recomputes the checksum and requires a valid signature by a trusted key, without the password; knowing the password does not let anyone forge it |
| Authenticity | Every entry is authenticated by its GCM tags and a sealed plaintext HMAC, and the header by the recipient block; `extract` and `list` reject anything modified, including when streaming |
| Cloud storage | Uploads become visible only when complete; reads pin the object version and fail if it is replaced, so an archive is never read as a mix of two versions. Archives are encrypted before they leave the machine |

## Trade-offs

**Compression.** Compressing before encrypting makes ciphertext size depend on how
compressible each file is, which weakly hints at file type and content to anyone who can
see the archive. Use `--no-compress` when archive sizes must reveal nothing beyond the
padded plaintext size.

**Solid mode.** Every file in a solid group is encrypted under the group's key, so key
isolation is per group rather than per file, and the archive reveals which small files
were packed together (the entry type byte marks solid groups). Member names, sizes, and
permissions are inside the encrypted stream. Solid mode is off unless `--solid` is given.

**Incremental archives.** An update appends only new data, so anyone who sees successive
versions of the archive learns roughly how much changed in each session, and
deduplication within one archive makes it smaller than the sum of its files. The same
content in two different incremental archives shares nothing, because the chunking
secret and keys differ.

**Signatures.** A signature proves which key signed the archive's exact bytes, and
reveals that key's public half to anyone holding the archive. It says nothing about who
can decrypt it. Any change, including an incremental update, invalidates it: updates
re-sign with `--sign` or remove the stale signature and say so.

**Recipient privacy.** age X25519 recipients are anonymous, but age's SSH stanzas and
most hardware-token stanzas carry a short fingerprint of the recipient key. Anyone
holding a candidate public key (for example from GitHub) can check whether it is a
recipient, though not decrypt anything. The archive also reveals which kinds of
credential open it, which `extract` reports when none of the supplied ones match.

## Package signing

The apt and dnf repositories are signed with a dedicated key,
`C288 2C4E 61C3 846A 5302  3BD8 8455 419A 7567 D512` (`sarc packages`). Release archives
are listed with their SHA-256 hashes in each release's `checksums.txt`.
