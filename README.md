# sarc

[![CI](https://github.com/iamvirul/sarc/actions/workflows/ci.yml/badge.svg)](https://github.com/iamvirul/sarc/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/iamvirul/sarc)](https://github.com/iamvirul/sarc/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Secure Anti-Deduplication Archive.** sarc packs files into an encrypted archive whose
ciphertext never repeats: the same file archived twice looks completely different, so
nobody can tell which archives share content. Every byte is authenticated, and file
names, sizes, and attributes stay hidden without a credential.

## Features

- **Strong encryption**: AES-256-GCM with a separate key per file, random padding, and
  variable chunk sizes that defeat deduplication and fingerprinting.
- **Flexible unlocking**: passwords, key files, age and SSH public keys, and hardware
  tokens, with several recipients per archive.
- **Smaller archives**: zstd compression, and solid mode for many small files.
- **Backups**: incremental archives that store only what changed, split volumes, and SSH
  signatures to prove who made an archive.
- **Anywhere**: stream through pipes, or archive straight to Amazon S3, Google Cloud
  Storage, or Azure Blob Storage with no temporary file.
- **Faithful and safe**: keeps permissions, times, links, and extended attributes, and
  never writes outside the output directory.

## Install

**Homebrew** (macOS and Linux):

```bash
brew install iamvirul/sarc/sarc
```

**Debian and Ubuntu** (amd64, arm64):

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://iamvirul.github.io/sarc/sarc.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/sarc.gpg
echo "deb [signed-by=/etc/apt/keyrings/sarc.gpg] https://iamvirul.github.io/sarc/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/sarc.list
sudo apt update && sudo apt install sarc
```

**Fedora, RHEL, and other dnf systems** (x86_64, aarch64):

```bash
sudo curl -fsSL -o /etc/yum.repos.d/sarc.repo https://iamvirul.github.io/sarc/rpm/sarc.repo
sudo dnf install sarc
```

The package repositories are signed with key
`C288 2C4E 61C3 846A 5302  3BD8 8455 419A 7567 D512`.

**Go** (1.26 or later):

```bash
go install github.com/iamvirul/sarc/cmd/sarc@latest
```

**Docker**: `docker run --rm -v "$PWD:/data" ghcr.io/iamvirul/sarc --help`

**Binaries** for Linux, macOS, and Windows are on the
[releases page](https://github.com/iamvirul/sarc/releases). Check a download against the
release's `checksums.txt`:

```bash
sha256sum --check --ignore-missing checksums.txt
```

## Quick start

```bash
# Archive files and folders
sarc archive --password "correct-horse-battery" --output backup.sarc report.pdf photos/

# See what is inside
sarc list --password "correct-horse-battery" --archive backup.sarc

# Restore
sarc extract --password "correct-horse-battery" --archive backup.sarc --output ./restored/

# Check for corruption, no password needed
sarc verify --archive backup.sarc
```

A few more things sarc can do:

```bash
# Share with a teammate's age or SSH public key
sarc archive --recipient "$(cat ~/.ssh/id_ed25519.pub)" --output shared.sarc files/

# Back up only what changed since the last run
sarc archive --password "correct-horse-battery" --incremental --output backup.sarc ./data/

# Archive straight to cloud storage
sarc archive --password "correct-horse-battery" --output s3://my-bucket/backup.sarc ./data/
```

## Documentation

| Guide | Contents |
|---|---|
| [Usage](docs/usage.md) | Every command: credentials, compression, incremental backups, split archives, signing, pipes, cloud storage, metadata |
| [Security model](docs/security.md) | What sarc protects, how, and the trade-offs of each option |
| [Performance](docs/performance.md) | Throughput targets, benchmarks against zip, archive sizes |
| [Architecture](docs/ARCHITECTURE.md) | Package layout and the on-disk format |
| [Changelog](CHANGELOG.md) | Release history |

## Building from source

```bash
git clone https://github.com/iamvirul/sarc.git
cd sarc
go build -o sarc ./cmd/sarc
go test -race ./...
```

## License

[MIT](LICENSE)
