# Shadow - High-Security File Encryption System

A high-security, high-performance file encryption system written in Rust with reversible filename obfuscation and state-of-the-art cryptographic protections.

## Development Status

## Development Status

🎯 **Phase 27 COMPLETED** - Multi-File Algorithm Support!

✅ **Universal Algorithm Selection**: All operations (single, multi-file, glob patterns) respect `--algorithm` flag consistently  
✅ **Enhanced Security Everywhere**: Multi-file operations use XChaCha20-Poly1305 by default for enhanced security  
✅ **Mixed Algorithm Support**: Universal decryption handles file sets with different algorithms transparently  
✅ **Zero Breaking Changes**: All existing workflows enhanced without disruption  
✅ **Complete Test Coverage**: All 177 tests pass with comprehensive algorithm dispatch validation  
✅ **Real-world Validated**: Practical testing confirms algorithm selection works across all operation types  

**Next Priority**: Code quality polish and production readiness.

## Features

- **Universal Algorithm Selection**: Choose between AES-256-GCM (compatibility) and XChaCha20-Poly1305 (enhanced security) for all operations
- **Multi-File Algorithm Support**: Algorithm selection works across single files, multiple files, and glob patterns
- **XChaCha20-Poly1305** authenticated encryption (eliminates nonce reuse vulnerabilities)
- **AES-256-GCM** authenticated encryption (backward compatibility)
- **Mixed Algorithm Decryption**: Universal decryption handles file sets with different algorithms transparently
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
# Uses XChaCha20-Poly1305 for enhanced security
./target/release/shadow secret.txt

# Encrypt with explicit XChaCha20-Poly1305 (default, enhanced security)
./target/release/shadow --algorithm xchacha20 secret.txt

# Encrypt with AES-256-GCM (maximum compatibility)
./target/release/shadow --algorithm aes-gcm secret.txt

# Encrypt with minimal output (quiet mode)
./target/release/shadow --quiet secret.txt

# Encrypt with filename obfuscation
./target/release/shadow --obfuscate secret.txt

# Encrypt with algorithm selection and obfuscation (using default XChaCha20-Poly1305)
./target/release/shadow --obfuscate secret.txt

# Encrypt with explicit algorithm and obfuscation
./target/release/shadow --algorithm aes-gcm --obfuscate secret.txt

# Encrypt and remove source file
./target/release/shadow --remove-source secret.txt

# Decrypt a file (password prompted securely, progress shown by default)
./target/release/unshadow secret.txt.shadow

# Decrypt with minimal output (quiet mode)
./target/release/unshadow --quiet secret.txt.shadow

# Decrypt with filename obfuscation and remove encrypted file  
./target/release/unshadow --inplace secret.txt.shadow

# Multi-file encryption with default XChaCha20-Poly1305 (enhanced security)
./target/release/shadow file1.txt file2.txt file3.txt

# Multi-file encryption with explicit algorithm selection
./target/release/shadow --algorithm aes-gcm file1.txt file2.txt file3.txt

# Multi-file encryption with glob patterns (uses default XChaCha20-Poly1305)
./target/release/shadow *.txt
./target/release/shadow "docs/**/*.txt"

# Multi-file encryption with algorithm selection and glob patterns
./target/release/shadow --algorithm xchacha20 "sensitive/**/*.txt"

# Decrypt multiple files (universal decryption handles mixed algorithms)
./target/release/unshadow file1.shadow file2.shadow file3.shadow

# Decrypt with glob patterns (works with any algorithm combination)
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

**Latest Update**: ✅ **Phase 26 Complete** - XChaCha20-Poly1305 Default Migration with enhanced security by default while maintaining full backward compatibility.

**Security Status**: ✅ **Enhanced Security by Default** - XChaCha20-Poly1305 provides 2^-96 nonce collision resistance by default, with AES-256-GCM available for maximum compatibility via `--algorithm aes-gcm`.

**Quality Status**: ✅ **Exceptional Code Quality Maintained** - 147 tests passing including 30 comprehensive XChaCha20-Poly1305 security validation tests.

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