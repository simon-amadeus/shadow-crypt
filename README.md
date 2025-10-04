# Shadow

# Shadow

**⚠️ REWRITE IN PROGRESS - v0.13.0**

**Rewrite Status**: 🎯 **Domain Entities Foundation** - Complete domain layer implementation ready for services  
**Current Version**: v0.13.0 - All five core domain entities fully implemented per architectural specifications  
**Next Priority**: Domain Services layer (EncryptionService, DecryptionService, ListingService, MigrationService)

---

## Rewrite Progress

### ✅ **Completed (v0.13.0)**
- **Complete Domain Entities**: All five core entities fully implemented according to specifications
  - **FileMetadata**: Cross-platform metadata extraction with file type detection
  - **PlaintextFile**: Content loading, SHA-256 hashing, and metadata integration
  - **EncryptedFile**: Algorithm ID handling and TLV header integration
  - **CryptoSession**: Secure key material management with automatic zeroization
  - **DuplicateDetector**: Production-ready content hash database with multi-path scanning
- **Comprehensive Testing**: 7 new unit tests plus existing test suite - all 128+ tests passing
- **Architectural Foundation**: Clean entity interfaces ready for domain services layer
- **Memory Safety**: SecureBox integration and automatic key material zeroization

### ✅ **Previous Foundation (v0.9.0-0.12.0)**
- **Content Fingerprinting Infrastructure**: Complete SHA-256 content hashing system for duplicate detection
- **TLV ContentHash Integration**: Seamless storage/retrieval of content hashes in encrypted file headers
- **File Detection Service**: Complete FileDetector with magic number validation and double-encryption prevention
- **Crypto Interface Resolution**: Fixed KeyMaterial size mismatch and algorithm integration
- **Error Handling Framework**: Security-conscious, user-friendly error system with CLI exit codes

### ✅ **Core Foundation (v0.8.1-0.8.2)**
- **Clean Architecture Compliance**: Complete domain/infrastructure separation following dependency inversion
- **Dual Algorithm Support**: AES-256-GCM and XChaCha20-Poly1305 with unified interfaces
- **TLV Header System V1**: Extensible Type-Length-Value format with version compatibility matrix
- **Migration Service**: Complete migration orchestration with safety checks and backup/restore

### 🚧 **Next Priorities (P1)**
- **Domain Services Implementation**: EncryptionService, DecryptionService, ListingService, MigrationService
- **Repository Interfaces**: FileRepository and PasswordRepository implementations  
- **Application Workflows**: Complete user-facing workflow orchestration
- **CLI Integration**: Connect domain services to CLI binaries

### 📋 **Implementation Strategy**
**Architecture Guide**: Follow `docs/specs/DOMAIN_ARCHITECTURE.md` and `docs/specs/ARCHITECTURE_REQUIREMENTS.md`  
**Legacy Reference**: Proven patterns available in `legacy/src/` for extraction and clean reimplementation  
**Testing**: 128+ tests covering domain entities, content fingerprinting, and cryptographic operations

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