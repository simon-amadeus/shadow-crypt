# Shadow

**⚠️ REWRITE IN PROGRESS - v0.19.0**

**Rewrite Status**: 🎯 **Filename Obfuscation Complete** - Enhanced privacy features fully operational  
**Current Version**: v0.19.0 - Complete filename obfuscation for enhanced privacy during encryption  
**Next Priority**: Additional CLI binaries (unshadow, shadows, shadowmigrate)

---

## Production Features (v0.19.0)

### ✅ **Shadow Binary (Complete)**
- **Real File Encryption**: XChaCha20-Poly1305 and AES-256-GCM algorithms with production crypto operations
- **Filename Obfuscation**: `--obfuscate` flag for enhanced privacy using cryptographically secure UUID generation
- **Professional UX**: User-friendly output formatting, progress reporting, and comprehensive error handling  
- **Batch Processing**: Multiple file encryption with individual success/failure tracking and result summaries
- **File Lifecycle**: Configurable source removal/preservation using --keep flag
- **Safety Features**: Double-encryption prevention with clear error messages and override options
- **Algorithm Selection**: Simple algorithm choice (xchacha20/aes-gcm) with proper validation
- **Progress Control**: Real-time encryption feedback with --quiet mode for silent operation

### Usage Examples
```bash
# Encrypt single file (removes source)
./target/debug/shadow document.txt

# Encrypt with filename obfuscation for enhanced privacy
./target/debug/shadow --obfuscate secret_document.pdf

# Encrypt with source preservation  
./target/debug/shadow --keep document.txt

# Batch encrypt with AES-GCM and obfuscation
./target/debug/shadow --algorithm aes-gcm --obfuscate *.txt

# Silent operation with all privacy features
./target/debug/shadow --quiet --keep --obfuscate files/*.doc
```

## Rewrite Progress

### ✅ **Completed Architecture (v0.19.0)**
- **Filename Obfuscation**: Complete privacy enhancement with UUID-based filename obfuscation and automatic restoration
- **Complete CLI Integration**: Production-ready shadow binary with end-to-end file encryption functionality
- **Real Crypto Operations**: EncryptionWorkflow → EncryptionService → Infrastructure crypto integration  
- **Application Workflows**: Full workflow orchestration with EncryptionWorkflow operational
- **Repository Interfaces**: Complete infrastructure abstraction with FileRepository and PasswordRepository
- **Domain Layer Foundation**: All entities, services, and cryptographic abstractions per architectural specs
- **Content Fingerprinting**: SHA-256 content hashing with duplicate detection capabilities
- **TLV Header System**: Extensible format supporting algorithm detection and version compatibility
- **Memory Safety**: Automatic key material zeroization and secure data handling

### 🚧 **Next Priorities (P3)**
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