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

# Extract
sarc extract --password "StrongPass123" --archive backup.sarc --output ./restored/

# Verify archive integrity (no password required)
sarc verify --archive backup.sarc

# List contents (password required to decrypt filenames)
sarc list --password "StrongPass123" --archive backup.sarc
```

## Security model

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM per block |
| Key isolation | PBKDF2-SHA256, 100k iterations, unique 32-byte salt per file |
| Integrity | GCM auth tag per block + HMAC-SHA256 over full plaintext |
| Deduplication resistance | Random padding (1-4 KB header, 512-2048 B trailer), variable chunk sizes (64 KB +/- 8 KB), unique nonce per block |
| Metadata protection | Filename AES-encrypted, size bucketed (not exact), timestamps day-truncated and hashed |
| Container integrity | HMAC-SHA256 over entire archive body, verified by `sarc verify` without decryption |

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
