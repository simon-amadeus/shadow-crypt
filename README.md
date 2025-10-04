# Shadow

# Shadow

**⚠️ REWRITE IN PROGRESS - v0.15.0**

**Rewrite Status**: 🎯 **Repository Interfaces Foundation** - Complete infrastructure abstraction layer ready for application workflows  
**Current Version**: v0.15.0 - Repository interfaces with both standard and mock implementations fully operational  
**Next Priority**: Application Workflows (EncryptionWorkflow, DecryptionWorkflow, ListingWorkflow, MigrationWorkflow)

---

## Rewrite Progress

### ✅ **Completed (v0.15.0)**
- **Complete Repository Interfaces**: Full infrastructure abstraction layer with production and testing implementations
  - **FileRepository**: Atomic file operations, secure deletion, and comprehensive metadata handling
  - **PasswordRepository**: Secure password input, confirmation, and strength validation
  - **Standard Implementations**: Production-ready StandardFileRepository and StandardPasswordRepository
  - **Mock Implementations**: Full-featured test infrastructure with operation tracking and failure simulation
- **Enhanced Security**: Cryptographic secure deletion, atomic write operations, and memory-safe password handling
- **Comprehensive Testing**: 12 integration tests covering all repository operations and error scenarios
- **Clean Architecture**: Proper dependency inversion with infrastructure → domain direction

### ✅ **Foundation (v0.13.0-0.14.0)**
- **Complete Domain Layer**: All entities and services fully implemented per architectural specifications
- **Content Fingerprinting**: SHA-256 content hashing integrated throughout domain layer
- **TLV Header System**: Extensible format with algorithm detection and version compatibility
- **Memory Safety**: Automatic key material zeroization and secure data handling

### 🚧 **Next Priorities (P1)**
- **Application Workflows**: EncryptionWorkflow, DecryptionWorkflow, ListingWorkflow, MigrationWorkflow
- **CLI Integration**: Connect domain workflows to CLI binaries
- **End-to-End Testing**: Complete user workflow validation

### 📋 **Implementation Strategy**
**Architecture Guide**: Follow `docs/specs/DOMAIN_ARCHITECTURE.md` and `docs/specs/ARCHITECTURE_REQUIREMENTS.md`  
**Legacy Reference**: Proven patterns available in `legacy/src/` for extraction and clean reimplementation  
**Testing**: 140+ tests covering full domain layer and infrastructure abstractions

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