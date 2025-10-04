# Shadow

**⚠️ REWRITE IN PROGRESS - v0.9.0**

**Rewrite Status**: 🎯 **Content Fingerprinting & Duplicate Detection** - Complete SHA-256 infrastructure for duplicate detection  
**Current Version**: v0.9.0 - Production-ready content fingerprinting with TLV integration  
**Next Priority**: EncryptionService integration and CLI duplicate handling workflows

---

## Rewrite Progress

### ✅ **Completed (v0.9.0)**
- **Content Fingerprinting Infrastructure**: Complete SHA-256 content hashing system for duplicate detection
- **DuplicateDetector Entity**: Production-ready duplicate detection with O(1) ContentHashDatabase performance
- **TLV ContentHash Integration**: Seamless storage/retrieval of content hashes in encrypted file headers
- **Builder Pattern Architecture**: Fluent configuration enabling clean EncryptionService integration
- **Security-Conscious Design**: File I/O errors no longer expose sensitive system details, chunked reading prevents memory exhaustion
- **Comprehensive Testing**: All 141 tests pass (112 unit + 29 integration/doc) with performance validation up to 100 files

### ✅ **Previous Foundation (v0.8.2)**
- **File Detection Service**: Complete FileDetector with magic number validation and double-encryption prevention
- **Crypto Interface Resolution**: Fixed KeyMaterial size mismatch (96-byte HKDF to 32-byte algorithm keys)
- **Enhanced Domain Architecture**: PlaintextFile and EncryptedFile with proper APIs and DecryptionService scaffold
- **Service Integration**: Clean FileDetector integration with EncryptionService workflow validation

### ✅ **Core Foundation (v0.8.1)**
- **Error Handling Framework**: Security-conscious, user-friendly error system with CLI exit codes and actionable guidance
- **Dual Algorithm Support**: AES-256-GCM and XChaCha20-Poly1305 with unified interfaces and secure memory management
- **Clean Architecture Compliance**: Complete domain/infrastructure separation following dependency inversion
- **TLV Header System V1**: Extensible Type-Length-Value format with version compatibility matrix
- **Migration Service**: Complete migration orchestration with safety checks and backup/restore

### 🚧 **Next Priorities (P1)**
- **EncryptionService Integration**: Leverage DuplicateDetector for pre-encryption duplicate checking
- **CLI Duplicate Workflows**: User prompts and handling when duplicate content detected
- **Double Password Verification**: CLI confirmation prompts for encryption operations

### 📋 **Implementation Strategy**
**Architecture Guide**: Follow `docs/specs/DOMAIN_ARCHITECTURE.md` and `docs/specs/ARCHITECTURE_REQUIREMENTS.md`  
**Legacy Reference**: Proven patterns available in `legacy/src/` for extraction and clean reimplementation  
**Testing**: 141+ tests covering domain architecture, content fingerprinting, and cryptographic operations

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