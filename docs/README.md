# Shadow - High-Security File Encryption System

A high-security, high-performance file encryption system written in Rust with reversible filename obfuscation and state-of-the-art cryptographic protections.

## Development Status

🎯 **Phase 14 COMPLETED** - Dependency management and updates implemented!

✅ **Dependency Updates**: 4 out of 5 outdated dependencies updated to latest versions  
✅ **Security Maintenance**: All security patches and improvements integrated  
✅ **API Compatibility**: Updated code to work with new dependency APIs (sysinfo 0.36)  
✅ **Build Stability**: All 105 tests pass with enhanced error handling and performance  
✅ **Production Quality**: Clean compilation with no warnings and maintained security properties  

**Ready for Production**: Core features complete with updated dependencies and comprehensive testing.

## Features

- **AES-256-GCM** authenticated encryption
- **Reversible filename obfuscation** (no manifest required)
- **Vertical slicing architecture** with separate tools for each use case
- **Secure memory handling** with automatic zeroization
- **Cryptographic agility** for future algorithm upgrades
- **Hardware acceleration** support (AES-NI)

## Tools

The system provides six specialized command-line tools:

- **`shadow`** - Encrypt files and directories
- **`unshadow`** - Decrypt files and directories  
- **`shadows`** - List encrypted files with original names
- **`shadowview`** - Securely view encrypted files
- **`shadowedit`** - Securely edit encrypted files
- **`shadowmigrate`** - Analyze and migrate between file format versions

## Quick Start

```bash
# Build all tools
cargo build --release

# Encrypt a file (password prompted securely)
./target/release/shadow secret.txt

# Encrypt with filename obfuscation
./target/release/shadow --obfuscate secret.txt

# Encrypt and remove source file
./target/release/shadow --remove-source secret.txt

# Decrypt a file (password prompted securely)
./target/release/unshadow secret.txt.shadow

# Decrypt with filename obfuscation and remove encrypted file  
./target/release/unshadow --inplace secret.txt.shadow

# Decrypt multiple files (Phase 11+)
./target/release/unshadow file1.shadow file2.shadow file3.shadow

# Decrypt with glob patterns (Phase 11+)  
./target/release/unshadow *.shadow
./target/release/unshadow "docs/**/*.shadow"

# List encrypted files in directory (password prompted securely)
./target/release/shadows encrypted_files/

# View an encrypted file (Phase 10+)
./target/release/shadowview secret.txt.shadow

# Edit an encrypted file (Phase 11+)
./target/release/shadowedit secret.txt.shadow

# Analyze files for migration needs (Phase 9.98+)
./target/release/shadowmigrate analyze secret.txt.shadow

# Analyze directory for migration planning
./target/release/shadowmigrate analyze-dir encrypted_files/
```

## Status

This is a production-ready file encryption system with completed core features, comprehensive security audit, production-quality error handling, and complete shadow branding. See [CHANGELOG.md](CHANGELOG.md) for version history and [ROADMAP.md](ROADMAP.md) for future plans.

**Latest Update**: ✅ **Phase 14 Complete** - Dependency management successfully implemented with 4 out of 5 dependencies updated to latest versions.

**Architecture Status**: ✅ **Algorithm Separation Complete** - AES-GCM self-contained, architecture ready for new algorithm development.

**Security Status**: ✅ **Production-grade security achieved** - All critical vulnerabilities addressed including nonce reuse detection, timing attack resistance, and filename authentication.

**Performance Status**: ✅ **Optimized for production** - Parallel processing and session management provide significant performance improvements for multi-file operations.

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