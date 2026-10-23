# sarc

Secure Anti-Deduplication Archive. Encrypts files with AES-256-GCM and defeats deduplication attacks through per-file random salts, variable-length chunk sizes, and random padding.

## Install

```bash
go install github.com/iamvirul/sarc/cmd/sarc@latest
```

Or download a signed release binary from the [Releases](https://github.com/iamvirul/sarc/releases) page. Each binary ships with a SLSA level-3 provenance file that can be verified with [slsa-verifier](https://github.com/slsa-framework/slsa-verifier).

## Usage

```bash
# Create an archive. Directories are archived recursively and restored with their
# structure: "folder/" is stored as folder/..., "." as paths relative to it. Symlinks and
# special files inside directories are skipped.
sarc archive --password "StrongPass123" --output backup.sarc file1.txt file2.bin folder/

# Parallel archive (defaults to NumCPU workers)
sarc archive --password "StrongPass123" --output backup.sarc --parallel 4 file1.txt

# Compression (zstd, before encryption). Default is auto: each file is compressed only
# if a probe of its first 64 KB shrinks by at least 5%, and known compressed formats
# (jpg, png, mp4, zip, gz, docx, ...) are skipped.
sarc archive --password "StrongPass123" --output backup.sarc --compress file.log      # always
sarc archive --password "StrongPass123" --output backup.sarc --no-compress file.log   # never
sarc archive --password "StrongPass123" --output backup.sarc --compress-level 19 a b  # 1-22, default 3

# Solid mode: pack files up to 1 MiB into shared groups (up to 8 MiB each) compressed as one
# stream. Much smaller archives of many small files, such as source trees.
sarc archive --password "StrongPass123" --output src.sarc --solid --compress-level 19 src/*

# Extract
sarc extract --password "StrongPass123" --archive backup.sarc --output ./restored/

# Multiple recipients: one archive, each person opens it with their own credential.
# Recipients are age public keys (inline age1... or a file of them), so age users need no
# extra tooling; others can create a key pair with sarc keygen.
sarc keygen --output bob.key                     # prints bob's public key (age1...)
sarc archive --password "alice-pass-123" --recipient age1... --recipient team.txt \
  --output shared.sarc report.pdf data.csv
sarc extract --password "alice-pass-123" --archive shared.sarc --output ./out
sarc extract --identity bob.key --archive shared.sarc --output ./out

# Key file instead of a password: nothing to remember or phish. Any file of 32 bytes to
# 1 MiB works; sarc keygen --keyfile writes a random 32-byte one (mode 0600). Keep a
# backup: a lost key file cannot be recovered.
sarc keygen --keyfile --output /Volumes/USB/backup.key
sarc archive --key /Volumes/USB/backup.key --output backup.sarc files/
sarc extract --key /Volumes/USB/backup.key --archive backup.sarc --output ./out

# Two factors: --key with --password makes them one credential, and both are required.
sarc archive --key device.key --password "second-factor" --output backup.sarc files/
sarc extract --key device.key --password "second-factor" --archive backup.sarc --output ./out

# SSH keys: archive for anyone's SSH public key, open with the private key (ed25519 or
# RSA; a passphrase-protected key prompts on the terminal). --identity on archive uses
# only the public half, so archiving never needs the passphrase.
sarc archive --recipient "$(cat ~/.ssh/id_ed25519.pub)" --output backup.sarc files/
sarc archive --identity ~/.ssh/id_ed25519 --output backup.sarc files/
sarc extract --identity ~/.ssh/id_ed25519 --archive backup.sarc --output ./out

# Hardware tokens through age plugins (age-plugin-yubikey, age-plugin-fido2-hmac,
# age-plugin-tpm, age-plugin-se, ...): the secret never leaves the device. sarc runs
# age-plugin-NAME from PATH; touch and PIN prompts go to the terminal, never to stdout.
age-plugin-yubikey --generate > yubikey.id                 # prints age1yubikey1...
sarc archive --recipient age1yubikey1... --output backup.sarc files/
sarc extract --identity yubikey.id --archive backup.sarc --output ./out

# Incremental backups: the first run creates the archive, each later run appends only
# data the archive does not hold yet, plus a record of changed and deleted files. Files
# whose size, modification time, and mode are unchanged are not even read, and a run
# with no changes writes nothing. extract and list show the latest state.
sarc archive --password "StrongPass123" --incremental --output backup.sarc ./data/
# created incremental archive: session 1, 100 file(s) (10.2 GB), 9871 chunk(s), 9.84 GB written
sarc archive --password "StrongPass123" --incremental --output backup.sarc ./data/
# session 2: 3 file(s) changed (412 MB), 97 unchanged, 1 deleted; appended 8.03 MB in 7 new chunk(s)
sarc extract --password "StrongPass123" --archive backup.sarc --output ./restored/

# Signing: prove who created an archive, not just that it is intact. Signatures are
# standard SSH signatures, so existing SSH keys work, and checking one needs no password.
sarc keygen --signing --output signing.key       # writes signing.key and signing.key.pub
sarc archive --password "pass" --sign signing.key --output release.sarc files/
sarc sign --signing-key ~/.ssh/id_ed25519 --archive old.sarc   # sign an existing archive
sarc verify --archive release.sarc --signer signing.key.pub
# signature VALID: signed by SHA256:2B5w0n/WSq... (ssh-ed25519), sarc signing key
# integrity check PASSED

# Check the archive checksum for corruption (no password required)
sarc verify --archive backup.sarc

# Streaming: "-" reads the archive from stdin or writes it to stdout, so archives can be
# piped to S3, ssh, or another process with no temporary archive file. Memory stays
# constant regardless of archive size.
sarc archive --password "StrongPass123" --output - files/* | aws s3 cp - s3://bucket/backup.sarc
curl -s https://example.com/backup.sarc | sarc extract --password "StrongPass123" --archive - --output ./out
sarc archive --password "StrongPass123" --output - files/* | ssh user@host "sarc extract --password 'StrongPass123' --archive - --output /backup/"

# List contents with codec and compression ratio (a credential is required to decrypt filenames)
sarc list --password "StrongPass123" --archive backup.sarc
```

`--compress-level` takes zstd's 1-22 scale; the pure-Go encoder maps it onto four speed
tiers (fastest, default, better, best), so neighbouring levels can produce identical output.

Archive size compared with zip, on Go source trees (zip with default settings):

| Tree | zip | sarc per-file (auto) | sarc `--solid` | sarc `--solid --compress-level 19` |
|---|---|---|---|---|
| `net/http` (113 files) | 616K | 888K | 557K (-10%) | 474K (-23%) |
| `runtime` (1088 files) | 4358K | 6721K | 3453K (-21%) | 2979K (-32%) |
| `cmd/go` (1496 files) | 1883K | 4933K | 1244K (-34%) | 1062K (-44%) |

Per-file mode stays larger than zip on small-file trees because every entry carries about
2.2 KB of random anti-deduplication padding; solid mode pays that once per group.

## Security model

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM per block |
| Key isolation | Random per-archive content key; a unique HKDF-SHA256 key per file from a unique 32-byte salt |
| Recipients | Content key wrapped once per password (PBKDF2-SHA256, 100k+ iterations, AES-256-GCM), once per key file (HKDF-SHA256, AES-256-GCM), once per key file + password pair (both combined in one HKDF), and once for all public-key recipients (age X25519, SSH, plugins); recipient public keys are not stored |
| Integrity | GCM auth tag per block + HMAC-SHA256 over full plaintext |
| Deduplication resistance | Random padding (1-4 KB header, 512-2048 B trailer), variable chunk sizes (64 KB +/- 8 KB), unique nonce per block |
| Metadata protection | Filename AES-encrypted, size bucketed (not exact), timestamps day-truncated and hashed |
| Compression | Optional zstd before encryption, per file; the codec is recorded inside the encrypted metadata |
| Solid groups (`--solid`) | Small files share one entry: one key, one padding set, one HMAC per group of up to 8 MiB |
| Incremental archives (`--incremental`) | Files are split into content-defined chunks (about 1 MiB) whose boundaries depend on a secret derived from the archive key; chunks are named by keyed HMAC, deduplicated within the archive, and packed into encrypted, padded pack entries, so chunk boundaries and identities never appear outside the encryption. The header seals the session count, so cutting off the newest sessions is detected |
| Container checksum | SHA-256 over the archive body in the footer, checked by `sarc verify` without a password. It is not keyed: it detects accidental corruption, not tampering |
| Provenance (`--sign`, `sign`) | Optional SSH signature (Ed25519, ECDSA, or RSA with SHA-512) over the footer checksum, appended after the footer. `verify --signer` recomputes the checksum and requires a valid signature by a trusted key, without the password; knowing the password does not let anyone forge it |
| Authenticity | Every entry is authenticated by its GCM tags and a sealed plaintext HMAC, and the header by the recipient block; `extract` and `list` reject anything modified, including when streaming |

Compression trade-off: compressing before encrypting makes ciphertext size depend on how
compressible each file is, which weakly hints at file type and content to anyone who can
see the archive. Use `--no-compress` when archive sizes must reveal nothing beyond the
padded plaintext size.

Solid trade-off: every file in a solid group is encrypted under the group's key, so key
isolation is per group rather than per file, and the archive reveals which small files
were packed together (the entry type byte marks solid groups). Member names, sizes, and
permissions are inside the encrypted stream. Solid mode is off unless `--solid` is given.

Incremental trade-off: an update appends only new data, so anyone who sees successive
versions of the archive learns roughly how much changed in each session, and
deduplication within one archive makes it smaller than the sum of its files. The same
content in two different incremental archives shares nothing, because the chunking
secret and keys differ. Restoring needs random access, so an incremental archive must be
extracted from a file, not a pipe.

Signature scope: a signature proves which key signed the archive's exact bytes, and
reveals that key's public half to anyone holding the archive. It says nothing about who
can decrypt it. Any change, including an incremental update, invalidates it: updates
re-sign with `--sign` or remove the stale signature and say so. Because signatures are
standard SSH signatures in the `sarc-archive` namespace over the 32-byte footer checksum,
`ssh-keygen -Y verify` can check them without sarc (see ARCHITECTURE.md).

Recipient privacy: age X25519 recipients are anonymous, but age's SSH stanzas and most
hardware-token stanzas carry a short fingerprint of the recipient key. Anyone holding a
candidate public key (for example from GitHub) can check whether it is a recipient,
though not decrypt anything. The archive also reveals which kinds of credential open it,
which `extract` reports when none of the supplied ones match.

## Benchmark

![Benchmark results](https://raw.githubusercontent.com/iamvirul/sarc/master/benchmarks/benchmark_results.png)

Benchmarks run automatically on every PR and compare sarc archive/extract throughput against zip on a random-data file. Results are committed to `benchmarks/benchmark_results.png` and posted as a PR comment.

| Runner | Max safe file size | Disk available |
|---|---|---|
| `ubuntu-latest` (free) | 5 GB | 14 GB |
| `ubuntu-latest-16-core` (Team/Enterprise) | 10 GB+ | 32 GB |

To increase the file size, set `TEST_FILE_GB` in `.github/workflows/benchmark.yml` and switch the runner accordingly.

## Performance targets

| Operation | Target |
|---|---|
| Encryption | 200-500 MB/s (parallel) |
| Decryption | 150-300 MB/s |
| Memory footprint | Constant: peak Go heap of about 25-45 MB to archive or extract, independent of file and archive size (archiving files of 64 MB or more memory-maps them, so RSS also counts reclaimable page cache) |
| Archive overhead | < 5% (padding + headers) |

## Building from source

```bash
git clone https://github.com/iamvirul/sarc.git
cd sarc
go build ./cmd/sarc
```

## Docker

```bash
docker build -t sarc .

docker run --rm -v $(pwd):/data sarc \
  archive --password "StrongPass123" --output /data/backup.sarc /data/file.txt

docker run --rm -v $(pwd):/data sarc \
  extract --password "StrongPass123" --archive /data/backup.sarc --output /data/restored/
```

## Verify a release binary

```bash
slsa-verifier verify-artifact sarc_linux_amd64 \
  --provenance-path sarc_linux_amd64.intoto.jsonl \
  --source-uri github.com/iamvirul/sarc \
  --source-tag v1.0.0
```

## License

MIT
