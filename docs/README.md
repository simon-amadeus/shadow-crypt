# Shadow - High-Security File Encryption System

A high-security, high-performance file encryption system written in Rust with reversible filename obfuscation and state-of-the-art cryptographic protections.

## Development Status

🎯 **Phase 20 COMPLETED** - Double-Encryption Prevention with smart detection and user guidance!

✅ **Smart Detection**: Shadow now prevents encrypting already encrypted files by checking for the "SHADOW" magic header  
✅ **Clear Error Messages**: Single file operations provide helpful error messages with guidance when attempting to encrypt `.shadow` files  
✅ **Multi-File Intelligence**: Batch operations skip already encrypted files with warnings rather than failing entirely  
✅ **User Safety**: Eliminates creation of double-encrypted files like `secret.txt.shadow.shadow` that provide no security benefit  

**Next Priority**: Software Architecture & Quality Audit - comprehensive code quality assessment and improvement recommendations.

## Features

- **AES-256-GCM** authenticated encryption
- **Reversible filename obfuscation** (no manifest required)
- **Vertical slicing architecture** with separate tools for each use case
- **Secure memory handling** with automatic zeroization
- **Cryptographic agility** for future algorithm upgrades
- **Hardware acceleration** support (AES-NI)
- **Universal progress indicators** with real-time performance feedback

## Tools

The system provides seven specialized command-line tools:

- **`shadow`** - Encrypt files and directories (progress indicators by default)
- **`unshadow`** - Decrypt files and directories (progress indicators by default)  
- **`shadows`** - List encrypted files with original names (progress indicators by default)
- **`shadowview`** - Securely view encrypted files
- **`shadowedit`** - Securely edit encrypted files
- **`shadowmigrate`** - Analyze and migrate between file format versions
- **`shadowbench`** - Performance analysis and system benchmarking

## Quick Start

```bash
# Build all tools
cargo build --release

# Encrypt a file (password prompted securely, progress shown by default)
./target/release/shadow secret.txt

# Encrypt with minimal output (quiet mode)
./target/release/shadow --quiet secret.txt

# Encrypt with filename obfuscation
./target/release/shadow --obfuscate secret.txt

# Encrypt and remove source file
./target/release/shadow --remove-source secret.txt

# Decrypt a file (password prompted securely, progress shown by default)
./target/release/unshadow secret.txt.shadow

# Decrypt with minimal output (quiet mode)
./target/release/unshadow --quiet secret.txt.shadow

# Decrypt with filename obfuscation and remove encrypted file  
./target/release/unshadow --inplace secret.txt.shadow

# Decrypt multiple files (Phase 11+)
./target/release/unshadow file1.shadow file2.shadow file3.shadow

# Decrypt with glob patterns (Phase 11+)  
./target/release/unshadow *.shadow
./target/release/unshadow "docs/**/*.shadow"

# List encrypted files in directory (progress shown by default)
./target/release/shadows encrypted_files/

# View an encrypted file (Phase 10+)
./target/release/shadowview secret.txt.shadow

# Edit an encrypted file (Phase 11+)
./target/release/shadowedit secret.txt.shadow

# Analyze files for migration needs (Phase 9.98+)
./target/release/shadowmigrate analyze secret.txt.shadow

# Analyze directory for migration planning
./target/release/shadowmigrate analyze-dir encrypted_files/

# Run performance benchmark and analysis
./target/release/shadowbench
```

## Status

This is a production-ready file encryption system with completed core features, comprehensive security audit, production-quality error handling, and complete shadow branding. See [CHANGELOG.md](CHANGELOG.md) for version history and [ROADMAP.md](ROADMAP.md) for future plans.

**Latest Update**: ✅ **Phase 20 Complete** - Double-Encryption Prevention with smart detection preventing user confusion and ensuring clean file management.

**Architecture Status**: ✅ **Algorithm Separation Complete** - AES-GCM self-contained, architecture ready for new algorithm development.

**Security Status**: ✅ **Production-grade security achieved** - All critical vulnerabilities addressed including nonce reuse detection, timing attack resistance, and filename authentication.

**Performance Status**: ✅ **Optimized for production** - Parallel processing and session management provide significant performance improvements for multi-file operations.

**User Experience Status**: ✅ **Professional UX implemented** - Default progress indicators across all tools with clean architecture and --quiet option for automation.

**Code Quality Status**: ✅ **Production error handling implemented** - All production code uses proper error handling with comprehensive input validation.

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design and module structure
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and progress tracking  
- **[FUTURE_ROADMAP.md](FUTURE_ROADMAP.md)** - Development roadmap and planned features
- **[SECURITY_AUDIT.md](../SECURITY_AUDIT.md)** - Comprehensive security audit report
- **[specs/](specs/)** - Detailed technical specifications

## Contributing

See [FUTURE_ROADMAP.md](FUTURE_ROADMAP.md) for development phases and contribution opportunities.

## Development

```bash
# Build all tools
cargo build --release

# Run all tests
cargo test

# Run specific tool with help
cargo run --bin shadow -- --help
cargo run --bin unshadow -- --help
cargo run --bin shadows -- --help
cargo run --bin shadowmigrate -- --help
```

## License

MIT OR Apache-2.0

## Contributing

See [FUTURE_ROADMAP.md](FUTURE_ROADMAP.md) for planned features and implementation phases.