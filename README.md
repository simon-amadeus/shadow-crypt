# Shadow

**⚠️ REWRITE IN PROGRESS - v0.8.0**

**Rewrite Status**: 🎯 **Dual Algorithm Support** - AES-256-GCM and XChaCha20-Poly1305 implementations complete  
**Current Version**: v0.8.0 - Complete cryptographic foundation with algorithm choice  
**Next Priority**: Error handling framework and file detection logic

---

## Rewrite Progress

### ✅ **Completed (v0.8.0)**
- **AES-256-GCM Algorithm**: Complete implementation with secure 12-byte nonce generation alongside XChaCha20-Poly1305
- **Unified Error Handling**: All cryptographic operations consistently return `DomainError` for improved user experience
- **Algorithm Factory**: Enum-based pattern supporting both algorithms with unified interfaces
- **Clean Architecture Compliance**: Complete domain/infrastructure separation following dependency inversion
- **Domain-Driven Cryptography**: Core abstractions (`AlgorithmId`, `KeyMaterial`, `CryptographicAlgorithm`) in domain layer
- **Secure Memory Management**: Enhanced `KeyMaterial` with automatic zeroization and constant-time operations
- **TLV Header System V1**: Extensible Type-Length-Value format preserving proven V3 patterns
- **Configuration Providers**: Clean separation with domain interfaces and infrastructure implementations
- **Version Compatibility Matrix**: Future-proof migration system with V1 baseline and V3→V1 migration path
- **Migration Service**: Complete migration orchestration with safety checks and backup/restore
- **Error Handling Framework**: Security-conscious, user-friendly error system with actionable guidance

### 🚧 **Next Priorities (P0)**
- **Error Handling Framework**: User-friendly, security-conscious error messages with actionable guidance
- **File Detection Logic**: Robust double-encryption prevention using magic number validation
- **Content Fingerprinting**: SHA-256 infrastructure for duplicate detection using TLV ContentHash field

### 📋 **Implementation Strategy**
**Architecture Guide**: Follow `docs/specs/DOMAIN_ARCHITECTURE.md` and `docs/specs/ARCHITECTURE_REQUIREMENTS.md`  
**Legacy Reference**: Proven patterns available in `legacy/src/` for extraction and clean reimplementation  
**Testing**: 139+ tests covering domain architecture, cryptographic abstractions, and version compatibility

---

## Legacy Implementation (Still Functional)

Simple, secure file encryption with modern cryptography.

### Install

```bash
cargo install shadow-crypt
```

### Basic Usage

```bash
# Encrypt files
shadow document.txt
shadow *.pdf

# Decrypt files  
unshadow document.txt.shadow
unshadow *.shadow

# List encrypted files
shadows
```

### Advanced Options

```bash
# Obfuscate filenames for privacy
shadow --obfuscate secret.txt

# Choose encryption algorithm
shadow --algorithm aes-gcm file.txt    # for compatibility
shadow --algorithm xchacha20 file.txt  # for maximum security (default)
```

### Available Tools

- `shadow` - Encrypt files and directories
- `unshadow` - Decrypt files and restore original names  
- `shadows` - List and browse encrypted files

---

## Rewrite Architecture

The upcoming rewrite (see `docs/specs/`) will feature:

- **Modern Clean Architecture**: Hexagonal architecture with domain-driven design
- **Enhanced Security**: Double password verification, duplicate detection
- **Improved UX**: Source removal by default, `--keep` flag, progress indicators
- **Stateless Design**: No persistent configuration, pure CLI operation
- **Future-Proof**: Extensible V1 TLV header system for algorithm evolution

## Current Security Features

- **XChaCha20-Poly1305** and **AES-256-GCM** encryption algorithms
- **Argon2id** password-based key derivation
- **Authenticated encryption** with tamper detection
- **Filename obfuscation** for metadata privacy
- **Secure password prompting** (never displayed)
- **Versioned file format** for future compatibility

## Development Status

**Current (0.36.0)**: Legacy implementation with functional encryption/decryption  
**Specifications**: Complete architectural documentation in `docs/specs/`  
**Next Phase**: Full rewrite implementation with modern architecture

See `docs/CHANGELOG.md` for detailed version information.

## License

MIT or Apache 2.0