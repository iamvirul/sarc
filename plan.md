# Secure Anti-Deduplication Archive System - Architecture & Implementation Guide

## Executive Summary
Build a fast, secure archiving system that prevents deduplication attacks by:
- Encrypting data **before** compression
- Adding random padding to break duplicate patterns
- Using per-file salts to prevent cross-file analysis
- Maintaining integrity without exposing duplicate information

---

## 1. Architecture Overview

```
INPUT FILES
    ↓
[Per-File Salting & Random Padding Layer]
    ↓
[AES-256-GCM Encryption]
    ↓
[Variable-Length Frame Structure]
    ↓
[Metadata Isolation Layer]
    ↓
[TAR-like Container Format]
    ↓
OUTPUT: .sarc (Secure Archive) File
```

---

## 2. Core Components & Specifications

### 2.1 Encryption Layer
**Algorithm:** AES-256-GCM (Galois/Counter Mode)
- **Why:** Provides both confidentiality and authentication
- **Per-file key derivation:** Use PBKDF2(master_password, salt, iterations=100000)
- **Nonce handling:** 12-byte random nonce per file block
- **Block size:** 64KB chunks (variable, not fixed - prevents pattern analysis)

**Implementation Prompt:**
```
Create an EncryptionManager that:
- Takes master password and returns a KeyDeriver
- For each file, generate unique salt (32 bytes random)
- Derive file-specific key: PBKDF2(password, salt, 100000 iterations, SHA-256)
- Encrypt in 64KB blocks with random nonce per block
- Include HMAC-SHA256 of plaintext for integrity verification (computed before encryption)
- Return: encrypted_data + nonce + tag + salt (all bundled per file)
```

### 2.2 Anti-Deduplication Layer
**Problem:** Attackers can identify duplicate files by analyzing ciphertext patterns

**Solution - Three-Layer Approach:**

#### Layer A: File-Level Randomization
```
For each file:
1. Generate random salt (32 bytes)
2. Prepend random padding (1-4KB random data)
3. Append random padding (512-2048 bytes random data)
4. Vary chunk sizes: 64KB ± random(0-8KB)
```

**Implementation Prompt:**
```
Create a PaddingManager that:
- For file header: add random(1024, 4096) bytes of cryptographically secure random data
- For file trailer: add random(512, 2048) bytes
- Vary block sizes: generate random offset between -8KB and +8KB for each 64KB block
- Store actual data size in encrypted metadata only
- Ensure padding is never reused (each file gets unique padding)
```

#### Layer B: Metadata Isolation
```
Never store plaintext metadata that reveals:
- Filenames (encrypt with file-specific key)
- File sizes (pad to ranges: 0-1KB, 1-10KB, 10-100KB, 100KB-1MB, >1MB)
- Modification times (round to nearest day, encrypt)
- Hash digests (don't store; compute on-demand after decryption)
```

**Implementation Prompt:**
```
Create a MetadataManager that:
- Encrypts filename with derived key
- Rounds timestamps to day precision (hash with salt)
- Size ranges: map actual size to range bucket (encrypted)
- Stores: encrypted_filename, size_bucket, encrypted_timestamp, file_order_only
- Never includes file hash or digest in archive metadata
- All metadata per-file encrypted separately
```

#### Layer C: Frame Randomization
```
Structure each file entry:
[Random Frame Header (32 bytes)]
[Encrypted Metadata Block (variable, 256-512 bytes)]
[Random Inter-block Padding (256-1024 bytes)]
[Encrypted File Data Blocks (variable chunks)]
[Random Trailer (256-512 bytes)]
[Integrity Tag (16 bytes - only authenticated, not for duplicate detection)]
```

**Implementation Prompt:**
```
Create a FrameBuilder that:
- Pre-pend random 32-byte header (not used for recovery, just obfuscation)
- Encrypt metadata as sealed block with unique nonce
- Add random padding between metadata and data (non-recoverable, discarded)
- Split file into variable-length chunks: base 64KB + random(-8KB, +8KB)
- Encrypt each chunk independently with unique nonce
- Compute HMAC-SHA256(plaintext) before encryption, store encrypted
- Append random trailer before final tag
- Preserve order for recovery (sequential file IDs only)
```

---

## 3. File Format Specification

### Archive Container Structure
```
[ARCHIVE HEADER]
  - Magic: "SARC" (4 bytes)
  - Version: 1 (2 bytes)
  - Archive-level salt: 32 bytes (used for password stretching)
  - File count: encrypted (8 bytes encrypted with master key)
  - Reserved: 32 bytes random

[FILE ENTRIES] (repeated for each file)
  [FILE ENTRY HEADER]
    - Entry type: 1 byte (0x01 = file)
    - Entry salt: 32 bytes (unique per file)
    - Frame header: 32 bytes random
    
  [ENCRYPTED METADATA BLOCK]
    - Size: 2 bytes (encrypted)
    - Content: {filename, size_bucket, timestamp_hash, permissions}
    - Nonce: 12 bytes (prepended, visible)
    - Auth tag: 16 bytes
    
  [INTER-BLOCK PADDING]
    - Random bytes: random(256, 1024)
    
  [ENCRYPTED DATA BLOCKS]
    - Block count: variable
    - Each block:
      * Chunk size indicator: 2 bytes (encrypted: actual_size or size_bucket)
      * Nonce: 12 bytes (visible)
      * Encrypted data: variable length
      * Auth tag: 16 bytes
      
  [FILE TRAILER]
    - Random bytes: random(256, 512)
    - Total plaintext hash: HMAC-SHA256(all plaintext) - encrypted
    - Entry checksum: 8 bytes (for file boundary detection only)

[ARCHIVE FOOTER]
  - Archive HMAC: HMAC-SHA256(entire encrypted archive) - stored plain for integrity
  - Reserved: 32 bytes
```

---

## 4. Security Guarantees vs Attack Vectors

### Attack Vector: Statistical Analysis of Ciphertext
- **Defense:** Random padding, variable chunk sizes, random frame headers
- **Residual risk:** Minimum (only file count leaks from archive size)

### Attack Vector: Size Pattern Analysis
- **Defense:** Size buckets (0-1KB, 1-10KB, 10-100KB, etc.)
- **Residual risk:** Attackers know approximate file size ranges

### Attack Vector: Timing Side-Channels
- **Defense:** Constant-time crypto operations (use crypto/subtle for comparisons)
- **Implementation Prompt:**
```
In decryption routine:
- Use crypto/subtle.ConstantTimeCompare for all tag verification
- Decrypt all blocks regardless of tag failure (fail at end)
- Add random(1-50ms) to total operation time
```

### Attack Vector: Frequency Analysis
- **Defense:** Every file gets unique nonce + salt, making patterns unrepeatable
- **Residual risk:** Multiple archives with same password could leak patterns (mitigate: use unique salt per archive)

---

## 5. Performance Optimization Prompts

### Prompt 1: Parallel Encryption
```
Create a ConcurrentArchiver that:
- Spawns N worker goroutines (N = num_CPUs)
- Each worker: reads file chunk → encrypts → writes to output buffer
- Use buffered channels: input_queue (1000 items), output_queue (100 items)
- Main thread: reads files sequentially, dispatches to workers
- Writers: merge encrypted blocks in original order
- Benchmark: should achieve 200-500 MB/s on modern hardware
```

### Prompt 2: Memory Efficiency
```
Create a StreamingArchiver that:
- Never loads entire file in memory
- For each file:
  1. Open filehandle
  2. Read 64KB chunk → add padding/nonce → encrypt → write to archive → free memory
  3. Maintain sliding window of last 64KB for HMAC computation
- Maximum memory footprint: ~200MB regardless of archive size
```

### Prompt 3: Decompression (Reverse Process)
```
Create a SafeExtractor that:
- Takes archive + master password
- For each file:
  1. Read entry header, extract salt
  2. Derive file-specific key (same PBKDF2)
  3. Decrypt metadata block (verify tag)
  4. Extract encrypted_filename, size_bucket
  5. Decrypt filename with file key
  6. Decrypt each data block in sequence (verify tags)
  7. Strip padding (payload size stored encrypted in metadata)
  8. Write decrypted file to disk
- Return: list of extracted files + integrity status
```

---

## 6. Implementation Roadmap (Go) - Git Commit Flow (30 Commits)

### Phase 1: Core Crypto (5 Commits)

```bash
git commit -m "Initialize SARC project structure"
# Create: go.mod, .gitignore, README, directory structure

git commit -m "Add AES-256-GCM encryption manager"
# crypto/encryption.go: EncryptionManager, block encryption with GCM, per-block nonces

git commit -m "Implement PBKDF2 key derivation"
# crypto/keyderiver.go: KeyDeriver struct, PBKDF2 100k iterations, file-specific salts

git commit -m "Add cryptographic padding generator"
# crypto/padding.go: RandomPadding, SecureRandomBytes, variable-length padding

git commit -m "Create integrity HMAC utilities"
# crypto/hmac.go: ComputeHMAC, VerifyHMAC, ConstantTimeCompare for tags
```

### Phase 2: Archive Format (4 Commits)

```bash
git commit -m "Define archive file format spec"
# archive/format.go: ArchiveHeader, FileEntry, FrameHeader, MetadataBlock, Trailer

git commit -m "Implement metadata encryption manager"
# archive/metadata.go: MetadataManager, EncryptFilename, SizeBucketize, TimestampHash

git commit -m "Build frame structure builder"
# archive/frames.go: FrameBuilder, AddRandomHeader, AddInterBlockPadding, VariableChunkSizer

git commit -m "Create archive writer interface"
# archive/writer.go: ArchiveWriter, WriteHeader, WriteFileEntry, WriteFooter
```

### Phase 3: I/O & Streaming (5 Commits)

```bash
git commit -m "Implement concurrent archiver"
# io/concurrent.go: ConcurrentArchiver, worker pool, input/output channels, ordering

git commit -m "Add memory-efficient streaming archiver"
# io/streaming.go: StreamingArchiver, ChunkReader, IncrementalHMAC, memory footprint

git commit -m "Build safe archive extractor"
# io/extractor.go: SafeExtractor, DecryptFileEntry, VerifyIntegrity, StripPadding

git commit -m "Create progress tracking system"
# io/progress.go: ProgressTracker interface, ConsoleProgressBar, metrics, reporting

git commit -m "Add error handling and recovery"
# io/errors.go: Custom error types, recoverable vs fatal, secure error messages
```

### Phase 4: CLI & Testing (16 Commits)

```bash
git commit -m "Implement CLI command structure"
# cmd/sarc/main.go: RootCmd via cobra, archive, extract, verify, list subcommands

git commit -m "Add archive command implementation"
# cmd/sarc/archive.go: Execute archive operation, validate inputs, progress display

git commit -m "Add extract command implementation"
# cmd/sarc/extract.go: Execute extract operation, password verification, file integrity

git commit -m "Add verify command implementation"
# cmd/sarc/verify.go: Check archive HMAC, list entries, report integrity status

git commit -m "Add list command implementation"
# cmd/sarc/list.go: Decrypt filenames, show size buckets, display entry count

git commit -m "Write crypto package unit tests"
# crypto/*_test.go: Encrypt/Decrypt roundtrip, key derivation, nonce uniqueness tests

git commit -m "Write archive format unit tests"
# archive/*_test.go: Metadata encryption, frame structure, size bucketization tests

git commit -m "Write I/O integration tests"
# io/*_test.go: Small files, large files, concurrent archive, memory footprint tests

git commit -m "Add deduplication resistance tests"
# tests/dedup_test.go: Same file twice all different, no repeating patterns, no correlation

git commit -m "Add security cryptographic tests"
# tests/security_test.go: Auth tag tampering, nonce reuse prevention, salt uniqueness tests

git commit -m "Add CLI integration tests"
# tests/cli_test.go: Archive extract roundtrip, password verification, invalid archive tests

git commit -m "Write performance benchmarks"
# benchmarks/bench_test.go: Encryption, decryption, memory usage, concurrency scaling tests

git commit -m "Add documentation and examples"
# README.md, ARCHITECTURE.md, examples/, contributing guide, security claims

git commit -m "Add logging and debug mode"
# cmd/sarc/flags.go: --debug flag, structured logging, performance metrics, no secrets

git commit -m "Create Docker build configuration"
# Dockerfile (multi-stage), docker-compose.yml, .dockerignore, container security

git commit -m "Release version 1.0.0"
# Tag v1.0.0, CHANGELOG entry, security audit checklist marked PASSED
```

**Total: 30 commits | Estimated time: 2-3 weeks | Zero Claude Co-authored tags**

---

## 7. Key Implementation Notes

### Don't Do This:
- ❌ Compress before encryption (leaks patterns)
- ❌ Reuse nonces (breaks GCM security)
- ❌ Use fixed chunk sizes (enables pattern analysis)
- ❌ Store file hashes in archive (enables duplicate detection)
- ❌ Use same salt across files (enables correlation)

### Do This:
- ✅ Encrypt before any transformation
- ✅ Generate random nonce per block (12 bytes from crypto/rand)
- ✅ Vary chunk sizes by ±random()
- ✅ Compute integrity hashes BEFORE encryption
- ✅ Unique salt per file + archive salt

### Performance Targets:
- Encryption speed: 200-500 MB/s (with parallelization)
- Decryption speed: 150-300 MB/s
- Memory footprint: <200MB (streaming)
- Archive overhead: <5% (padding + headers)

---

## 8. Testing Strategy

### Test 1: Deduplication Resistance
```
Prompt:
Create TestDeduplicationResistance that:
- Archives same 1GB file twice with same password
- Compares byte-for-byte: should be 100% different
- Archives same file in 2 separate archives: should be 100% different
- Verify: no repeating 16-byte patterns across different encrypted blocks
```

### Test 2: Correctness
```
Prompt:
Create TestRoundTrip that:
- For 100 random files (1KB - 100MB each)
  1. Create archive with password "test123"
  2. Extract all files
  3. Verify SHA-256(original) == SHA-256(extracted)
  4. Verify filenames match
- Should have 100% success rate
```

### Test 3: Security (Cryptographic)
```
Prompt:
Create TestCryptoSecurity that:
- Verify all nonces are unique across blocks
- Verify PBKDF2 uses correct iteration count (100k)
- Verify auth tags prevent tampering (flip random byte, decryption should fail)
- Verify key derivation is deterministic
```

---

## 9. Command-Line Interface Design

```bash
# Archive (compress + encrypt with deduplication resistance)
$ sarc archive \
  --password "SecurePassword123" \
  --output backup.sarc \
  --parallel 4 \
  file1.bin file2.txt folder/

# Extract (decrypt + decompress + verify integrity)
$ sarc extract \
  --password "SecurePassword123" \
  --archive backup.sarc \
  --output ./restored/

# Verify archive integrity (no decryption)
$ sarc verify \
  --archive backup.sarc

# List contents (requires password for filenames)
$ sarc list \
  --password "SecurePassword123" \
  --archive backup.sarc
```

---

## 10. Security Audit Checklist

Before releasing:
- [ ] All nonces generated with crypto/rand (not predictable)
- [ ] All file salts unique (32 bytes crypto/rand)
- [ ] PBKDF2 iterations ≥ 100,000
- [ ] GCM tag verification before any processing
- [ ] No plaintext leakage in error messages
- [ ] Constant-time comparisons for auth tags
- [ ] Random padding always included (never skipped for speed)
- [ ] Variable chunk sizes prevent pattern analysis
- [ ] Archive HMAC prevents tampering at container level

---

## References & Algorithms

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Encryption | AES-256-GCM | NIST SP 800-38D |
| Key Derivation | PBKDF2 | RFC 2898 |
| HMAC | HMAC-SHA256 | RFC 2104 |
| Random Generation | crypto/rand | Go stdlib |
| Block Mode | Galois/Counter | NIST approved |

---

**Target: Implement in Go for 200-500 MB/s throughput with zero duplicate pattern leakage.**