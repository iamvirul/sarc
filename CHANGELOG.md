# Changelog

## v1.0.0 (2026-07-19)

Initial release.

### Features

- AES-256-GCM encryption with per-block random nonces
- PBKDF2-SHA256 key derivation, 100k iterations, unique 32-byte salt per file
- Anti-deduplication: random padding, variable chunk sizes, per-file key isolation
- Metadata protection: encrypted filenames, size buckets, hashed timestamps
- Container-level HMAC-SHA256 for tamper detection without decryption
- Streaming archiver with < 200 MB memory footprint
- Concurrent archiver with configurable worker count (default: NumCPU)
- CLI commands: archive, extract, verify, list
- SLSA level-3 signed release binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64

### Security audit

- [x] All nonces generated with crypto/rand
- [x] All file salts unique, 32 bytes from crypto/rand
- [x] PBKDF2 iterations >= 100,000
- [x] GCM tag verified before any plaintext returned
- [x] Plaintext HMAC verified with crypto/subtle.ConstantTimeCompare before writing output
- [x] No plaintext leakage in error messages
- [x] Random padding always included, never skipped
- [x] Variable chunk sizes prevent pattern analysis
- [x] Archive HMAC prevents container-level tampering
