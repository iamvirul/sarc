# Using sarc

A guide to every sarc command and option. Run `sarc <command> --help` for the flag
reference.

- [Archive and extract](#archive-and-extract)
- [List and verify](#list-and-verify)
- [Credentials](#credentials)
  - [Passwords](#passwords)
  - [Key files](#key-files)
  - [Public-key recipients](#public-key-recipients)
  - [SSH keys](#ssh-keys)
  - [Hardware tokens](#hardware-tokens)
- [Compression and solid mode](#compression-and-solid-mode)
- [Incremental backups](#incremental-backups)
- [Split archives](#split-archives)
- [Signing](#signing)
- [Pipes and streaming](#pipes-and-streaming)
- [Cloud storage](#cloud-storage)
- [File metadata and owners](#file-metadata-and-owners)
- [Docker](#docker)
- [Shell completion](#shell-completion)

## Archive and extract

```bash
sarc archive --password "correct-horse-battery" --output backup.sarc report.pdf photos/
sarc extract --password "correct-horse-battery" --archive backup.sarc --output ./restored/
```

Directories are archived recursively and restored with their structure: `photos/` is
stored as `photos/...`, and `.` as paths relative to it. Extraction never writes outside
the output directory, whatever names or symlinks the archive holds.

Files are encrypted in parallel on all CPUs; `--parallel N` sets the worker count.

## List and verify

```bash
sarc list --password "correct-horse-battery" --archive backup.sarc
sarc verify --archive backup.sarc
```

`list` shows each entry's type and permissions (like `ls -l`), size class, codec, and
compression ratio. It needs a credential, because file names are encrypted. On a file or
a cloud object it reads only the header and the archive's encrypted directory, not the
file data.

`verify` checks the archive checksum for corruption without any credential, and the
signature if there is one (see [Signing](#signing)).

## Credentials

An archive can be opened by any one of several credentials, chosen when it is created.
Each one wraps the archive's random content key, so adding recipients does not weaken
the others.

### Passwords

`--password` (at least 8 characters) opens the archive on its own.

### Key files

A key file replaces the password: there is nothing to remember or phish. Any file of
32 bytes to 1 MiB works; `sarc keygen --keyfile` writes a random 32-byte one with mode
0600. Keep a backup, because a lost key file cannot be recovered.

```bash
sarc keygen --keyfile --output /Volumes/USB/backup.key
sarc archive --key /Volumes/USB/backup.key --output backup.sarc files/
sarc extract --key /Volumes/USB/backup.key --archive backup.sarc --output ./out
```

`--key` together with `--password` makes them one credential that needs both, for two
factors:

```bash
sarc archive --key device.key --password "second-factor" --output backup.sarc files/
sarc extract --key device.key --password "second-factor" --archive backup.sarc --output ./out
```

### Public-key recipients

One archive can be opened by several people, each with their own credential. Recipients
are [age](https://age-encryption.org) public keys, given inline (`age1...`) or as a file of
them, so age users need no extra tooling. Others can create a key pair with
`sarc keygen`, which prints the public key.

```bash
sarc keygen --output bob.key
sarc archive --password "alice-pass-123" --recipient age1... --recipient team.txt \
  --output shared.sarc report.pdf data.csv
sarc extract --password "alice-pass-123" --archive shared.sarc --output ./out
sarc extract --identity bob.key --archive shared.sarc --output ./out
```

### SSH keys

Archive for anyone's SSH public key (ed25519 or RSA) and open it with the private key. A
passphrase-protected key prompts on the terminal. `--identity` on `archive` uses only
the public half, so archiving never needs the passphrase.

```bash
sarc archive --recipient "$(cat ~/.ssh/id_ed25519.pub)" --output backup.sarc files/
sarc archive --identity ~/.ssh/id_ed25519 --output backup.sarc files/
sarc extract --identity ~/.ssh/id_ed25519 --archive backup.sarc --output ./out
```

### Hardware tokens

age plugins (`age-plugin-yubikey`, `age-plugin-fido2-hmac`, `age-plugin-tpm`,
`age-plugin-se`, ...) keep the secret on the device. sarc runs `age-plugin-NAME` from
`PATH`; touch and PIN prompts go to the terminal, never to stdout.

```bash
age-plugin-yubikey --generate > yubikey.id          # prints age1yubikey1...
sarc archive --recipient age1yubikey1... --output backup.sarc files/
sarc extract --identity yubikey.id --archive backup.sarc --output ./out
```

## Compression and solid mode

Files are compressed with zstd before encryption. The default, auto, compresses a file
only if a probe of its first 64 KB shrinks by at least 5%, and skips known compressed
formats (jpg, png, mp4, zip, gz, docx, ...).

| Flag | Effect |
|---|---|
| `--compress` | Compress every file |
| `--no-compress` | Store every file uncompressed |
| `--compress-level N` | zstd level 1-22, default 3 |

The pure-Go encoder maps levels onto four speed tiers, so neighbouring levels can produce
identical output.

`--solid` packs files of up to 1 MiB into shared groups of up to 8 MiB, compressed as one
stream. Archives of many small files, such as source trees, become much smaller (see
[performance](performance.md#archive-size)):

```bash
sarc archive --password "correct-horse-battery" --output src.sarc --solid --compress-level 19 src/
```

Compression and solid mode have security trade-offs; see
[security](security.md#trade-offs).

## Incremental backups

With `--incremental`, the first run creates the archive and each later run appends only
data the archive does not hold yet, plus a record of changed and deleted files. Files
whose size, modification time, and mode are unchanged are not even read, and a run with
no changes writes nothing. `extract` and `list` show the latest state.

```bash
sarc archive --password "correct-horse-battery" --incremental --output backup.sarc ./data/
# created incremental archive: session 1, 100 file(s) (10.2 GB), 9871 chunk(s), 9.84 GB written
sarc archive --password "correct-horse-battery" --incremental --output backup.sarc ./data/
# session 2: 3 file(s) changed (412 MB), 97 unchanged, 1 deleted; appended 8.03 MB in 7 new chunk(s)
sarc extract --password "correct-horse-battery" --archive backup.sarc --output ./restored/
```

An incremental archive is updated in place, so it must be a local file. Restoring needs
random access: extract it from a file or a cloud object, not a pipe.

## Split archives

`--split SIZE` writes volumes of at most `SIZE`, named `backup.sarc.001`, `.002`, and so
on, for upload limits or several drives. Units follow GNU split: `K`/`M`/`G` are powers
of 1024 and `KB`/`MB`/`GB` powers of 1000.

```bash
sarc archive --password "correct-horse-battery" --split 2GB --output backup.sarc files/
sarc extract --password "correct-horse-battery" --archive backup.sarc.001 --output ./out
sarc verify --archive backup.sarc
cat backup.sarc.* | sarc extract --password "correct-horse-battery" --archive - --output ./out
```

Name any volume, or the base name, to extract. A missing, damaged, reordered, or foreign
volume is reported by number, and `verify` checks that every volume is present and
intact.

## Signing

A signature proves who created an archive, not just that it is intact. Signatures are
standard SSH signatures, so existing SSH keys work, and checking one needs no password.

```bash
sarc keygen --signing --output signing.key       # writes signing.key and signing.key.pub
sarc archive --password "correct-horse-battery" --sign signing.key --output release.sarc files/
sarc sign --signing-key ~/.ssh/id_ed25519 --archive old.sarc
sarc verify --archive release.sarc --signer signing.key.pub
# signature VALID: signed by SHA256:2B5w0n/WSq... (ssh-ed25519), sarc signing key
# integrity check PASSED
```

`sarc sign` signs an existing archive without the password and without rewriting it,
replacing any earlier signature. `verify --signer` accepts an SSH public key, a `.pub`,
`authorized_keys`, or `allowed_signers` file, or a PEM public key, and fails unless one of
them made a valid signature. `ssh-keygen -Y verify` can check signatures without sarc (see
[ARCHITECTURE.md](ARCHITECTURE.md#signatures)).

## Pipes and streaming

`-` reads the archive from stdin or writes it to stdout, so archives move through pipes,
ssh, or HTTP with no temporary archive file. Memory stays constant regardless of archive
size. sarc refuses to write an archive to a terminal.

```bash
sarc archive --password "correct-horse-battery" --output - files/ | ssh user@host "cat > backup.sarc"
curl -s https://example.com/backup.sarc | sarc extract --password "correct-horse-battery" --archive - --output ./out
```

When the archive goes to stdout, progress goes to stderr.

## Cloud storage

`archive --output`, and `extract`, `list`, and `verify --archive`, accept storage URLs.
Archives are written straight to the store and read straight from it, with no local
temporary file.

| Store | URL |
|---|---|
| Amazon S3 and S3-compatible stores (MinIO, Cloudflare R2, Backblaze B2, Wasabi) | `s3://bucket/path/backup.sarc` |
| Google Cloud Storage | `gs://bucket/path/backup.sarc` |
| Azure Blob Storage | `azblob://container/path/backup.sarc` |
| Local file | `file:///absolute/path/backup.sarc` |

```bash
sarc archive --password "correct-horse-battery" --output s3://my-bucket/backups/2026-07-20.sarc ./data/
sarc list --password "correct-horse-battery" --archive s3://my-bucket/backups/2026-07-20.sarc
sarc extract --password "correct-horse-battery" --archive gs://my-bucket/backup.sarc --output ./restored/
sarc verify --archive azblob://my-container/backup.sarc
```

An upload appears only once it is complete. A failed or interrupted (Ctrl-C) upload is
discarded, so no partial archive is left behind. Reads reconnect if a long download
breaks, and fail rather than mix versions if the object is replaced meanwhile.

Credentials come from each store's usual sources:

| Store | Configuration |
|---|---|
| S3 | `AWS_REGION`, `AWS_PROFILE` or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, SSO, instance and pod roles. For S3-compatible stores, `AWS_ENDPOINT_URL_S3`, and `SARC_S3_PATH_STYLE=true` if the store needs path-style addressing |
| GCS | Application Default Credentials: `GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`, or the metadata server |
| Azure | `AZURE_STORAGE_CONNECTION_STRING`, or `AZURE_STORAGE_ACCOUNT` with `AZURE_STORAGE_KEY` or the default Azure credential chain (`az login`, managed identity) |

```bash
AWS_ENDPOINT_URL_S3=http://minio:9000 SARC_S3_PATH_STYLE=true \
  sarc archive --password "correct-horse-battery" --output s3://bucket/backup.sarc ./data/
```

Uploads hold a few parts in memory. S3 parts start at 16 MiB and grow, allowing archives
of about 1.7 TiB. Azure blocks are 16 MiB, allowing about 780 GiB. GCS uploads in 16 MiB
chunks.

`--split`, `--incremental`, and `sarc sign` modify local files in place, so they need a
local path.

## File metadata and owners

Permissions (including the executable bit), modification times, symlinks, hard links,
empty directories, and extended attributes (macOS resource forks, Linux POSIX ACLs) are
kept. Devices, sockets, and pipes are skipped.

Owners (numeric uid and gid) are recorded only with `--preserve-owner` and restored only
with `--preserve-owner` on extract, usually as root. Otherwise they are skipped with a
warning, as are setuid, setgid, and sticky bits.

```bash
sudo sarc archive --password "correct-horse-battery" --preserve-owner --output system.sarc /etc
sudo sarc extract --password "correct-horse-battery" --preserve-owner --archive system.sarc --output /restore
```

## Docker

Release images are published to the GitHub Container Registry:

```bash
docker run --rm -v "$PWD:/data" ghcr.io/iamvirul/sarc \
  archive --password "correct-horse-battery" --output /data/backup.sarc /data/file.txt
docker run --rm -v "$PWD:/data" ghcr.io/iamvirul/sarc \
  extract --password "correct-horse-battery" --archive /data/backup.sarc --output /data/restored/
```

## Shell completion

The Homebrew, apt, and dnf packages install completions for bash, zsh, and fish. For
other installs, generate them with `sarc completion`:

```bash
sarc completion bash > /etc/bash_completion.d/sarc
sarc completion zsh > "${fpath[1]}/_sarc"
sarc completion fish > ~/.config/fish/completions/sarc.fish
```
