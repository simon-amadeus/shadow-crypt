# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Contributing

When contributing, please:
- Add entries under `[Unreleased]` section
- Use the following order for sections: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`
- Keep descriptions clear and concise
- Use imperative mood for descriptions (e.g., "Add feature" not "Added feature")
- Reference issue/PR numbers where applicable

Example:
```markdown
### Added
- Add new encryption feature (#123)

### Changed
- Update default security parameters

### Fixed
- Fix memory leak in decryption routine (#124)
```

---

## [Unreleased]

### Added
- Add v2 file format: header fields (magic, version, salt, KDF parameters, nonces) are now authenticated as AEAD associated data, with domain separation between filename and content encryption to prevent ciphertext-swapping within a file; new files are written as v2, v1 files remain fully readable
- Add property-based tests (proptest) covering header round-trips, parser robustness on arbitrary bytes, and v2 domain-separation invariants

### Changed
- Cap concurrent Argon2 memory use with a 4 GiB global budget: parallel key derivations reserve their declared memory cost and expensive derivations are throttled instead of running one per core
- Return a nonzero exit code when any file fails to encrypt or decrypt, instead of always exiting 0
- Progress output now reports files as they complete rather than as they start

### Fixed
- Validate KDF parameters from untrusted headers in the listing workflow (previously only the decryption workflow validated them), closing a DoS via crafted files in a listed directory
- Make no-overwrite checks atomic with `File::create_new`, removing check-then-create races on both encryption and decryption output paths
- Reject filename ciphertexts longer than the u16 length field in the v2 header instead of silently truncating
- Remove modulo bias from random output filename generation
- Stop mutating the process working directory in a unit test that could race with other tests

## [1.1.0] - 2026-05-14

### Security
- Fix path traversal vulnerability: sanitize decrypted filenames with `file_name()` before writing output, preventing a malicious `.shadow` file from escaping the output directory
- Add upper-bound validation for KDF parameters read from file headers (memory ≤ 8 GiB, iterations ≤ 1000, parallelism ≤ 256, key size ≤ 64 bytes) to prevent DoS via crafted files
- Generate a unique salt and derived key per file in batch encryption so files encrypted in the same session cannot be correlated by comparing header salts

### Changed
- Output filename generation now uses `OsRng` directly, consistent with nonce and salt generation
- Encryption success output now includes a reminder that the source file was not deleted

### Fixed
- Replace magic constant `90` in `FileHeader::min_length()` with a self-documenting sum of field sizes that stays correct if the format changes

## [1.0.9] - 2025-11-02
### Fixed
- include dependency crates in docs.rs build

## [1.0.8] - 2025-11-02
### Changed
- Unpublish shadow-crypt-core and shadow-crypt-shell crates to prevent direct dependency
- Update documentation to reflect unified shadow-crypt crate usage

## [1.0.7] - 2025-10-31
### Changed
- Refactor binrary file names to reflect provided functionality

## [1.0.6] - 2025-10-26
### Changed
- Resuce default Argon2id memory cost from 4 GiB to 1 GiB

## [1.0.5] - 2025-10-25
### Fixed
- Remove redundant clap dependency from root crate

## [1.0.4] - 2025-10-25

### Changed
- Update CLI parsing to use clap's derive API

### Fixed
- Fix help and version flags to display cleanly without error messages
- Fix clippy warnings across all crates

### Added
- Add --version flag support to CLI commands
- Add help and version flags to shadows command

## [1.0.3] - 2025-10-25

### Changed
- Documentation updates and fixes

## [1.0.2] - 2025-10-25

### Changed
- Documentation updates and fixes

## [1.0.1] - 2025-10-25

### Changed
- Documentation updates and fixes

## [1.0.0] - 2025-10-25

### Added
- Initial stable release of Shadow Crypt
- XChaCha20-Poly1305 encryption with Argon2id key derivation
- Modular architecture with separate core, shell, and binary crates
- Memory-safe operations with automatic zeroization
- Cross-platform CLI tool (Windows, macOS, Linux)
- File format v1 with integrity verification
- Documentation and security overview
- CI/CD pipeline with automated testing
- `shadow` command for file encryption
- `unshadow` command for file decryption
- `shadows` command for listing encrypted files
- Secure password prompting with confirmation

### Security
- Zero-knowledge design with no password storage
- Forward secrecy with unique salts and nonces
- Authenticated encryption preventing tampering
- Automatic memory zeroization

---
