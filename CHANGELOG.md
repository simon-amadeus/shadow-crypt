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