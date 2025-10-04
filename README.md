# Shadow

**⚠️ REWRITE IN PROGRESS - v0.3.0**

**Rewrite Status**: 🚀 **Core Infrastructure Complete** - Version compatibility matrix and migration system implemented  
**Current Version**: v0.3.0 - Foundation architecture with version management  
**Next Priority**: Error handling framework and cryptographic foundation

---

## Rewrite Progress

### ✅ **Completed (v0.3.0)**
- **Clean Architecture**: Domain/Application/Infrastructure/CLI layers established
- **TLV Header System V1**: Extensible Type-Length-Value format preserving proven V3 patterns
- **Configuration Providers**: Algorithm abstraction with XChaCha20-Poly1305 and AES-256-GCM support
- **Version Compatibility Matrix**: Future-proof migration system with V1 baseline and V3→V1 migration path
- **Migration Service**: Complete migration orchestration with safety checks and backup/restore

### 🚧 **Next Priorities**
- **Error Handling Framework**: User-friendly, security-conscious error messages
- **Secure Memory Management**: KeyMaterial with SecureBox automatic zeroization
- **Algorithm Abstraction Layer**: Pluggable interface for cryptographic implementations
- **File Detection Logic**: Double-encryption prevention using magic number validation

### 📋 **Implementation Strategy**
**Architecture Guide**: Follow `docs/specs/DOMAIN_ARCHITECTURE.md` and `docs/specs/ARCHITECTURE_REQUIREMENTS.md`  
**Legacy Reference**: Proven patterns available in `legacy/src/` for extraction and clean reimplementation  
**Testing**: 20+ tests covering version compatibility, migration, and domain integration

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