# sarc

Secure Anti-Deduplication Archive. Encrypts files with AES-256-GCM and defeats deduplication attacks through per-file random salts, variable-length chunk sizes, and random padding.

## Install

```bash
go install github.com/iamvirul/sarc/cmd/sarc@latest
```

Or download a signed release binary from the [Releases](https://github.com/iamvirul/sarc/releases) page. Each binary ships with a SLSA level-3 provenance file that can be verified with [slsa-verifier](https://github.com/slsa-framework/slsa-verifier).

## Usage

```bash
# Create an archive
sarc archive --password "StrongPass123" --output backup.sarc file1.txt file2.bin folder/

# Parallel archive (defaults to NumCPU workers)
sarc archive --password "StrongPass123" --output backup.sarc --parallel 4 file1.txt

# Compression (zstd, before encryption). Default is auto: each file is compressed only
# if a probe of its first 64 KB shrinks by at least 5%, and known compressed formats
# (jpg, png, mp4, zip, gz, docx, ...) are skipped.
sarc archive --password "StrongPass123" --output backup.sarc --compress file.log      # always
sarc archive --password "StrongPass123" --output backup.sarc --no-compress file.log   # never
sarc archive --password "StrongPass123" --output backup.sarc --compress-level 19 a b  # 1-22, default 3

# Extract
sarc extract --password "StrongPass123" --archive backup.sarc --output ./restored/

# Verify archive integrity (no password required)
sarc verify --archive backup.sarc

# List contents with codec and compression ratio (password required to decrypt filenames)
sarc list --password "StrongPass123" --archive backup.sarc
```

`--compress-level` takes zstd's 1-22 scale; the pure-Go encoder maps it onto four speed
tiers (fastest, default, better, best), so neighbouring levels can produce identical output.

## Security model

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM per block |
| Key isolation | PBKDF2-SHA256 (100k iterations) once per archive, then a unique HKDF-SHA256 key per file from a unique 32-byte salt |
| Integrity | GCM auth tag per block + HMAC-SHA256 over full plaintext |
| Deduplication resistance | Random padding (1-4 KB header, 512-2048 B trailer), variable chunk sizes (64 KB +/- 8 KB), unique nonce per block |
| Metadata protection | Filename AES-encrypted, size bucketed (not exact), timestamps day-truncated and hashed |
| Compression | Optional zstd before encryption, per file; the codec is recorded inside the encrypted metadata |

Compression trade-off: compressing before encrypting makes ciphertext size depend on how
compressible each file is, which weakly hints at file type and content to anyone who can
see the archive. Use `--no-compress` when archive sizes must reveal nothing beyond the
padded plaintext size.
| Container integrity | HMAC-SHA256 over entire archive body, verified by `sarc verify` without decryption |

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
| Memory footprint | < 200 MB (streaming mode) |
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
