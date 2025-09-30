# Crypto - High-Security File Encryption System

A high-security, high-performance file encryption system written in Rust with reversible filename obfuscation and state-of-the-art cryptographic protections.

## Features

- **AES-256-GCM** authenticated encryption
- **Reversible filename obfuscation** (no manifest required)
- **Vertical slicing architecture** with separate tools for each use case
- **Secure memory handling** with automatic zeroization
- **Cryptographic agility** for future algorithm upgrades
- **Hardware acceleration** support (AES-NI)

## Tools

The system provides five specialized command-line tools:

- **`lock`** - Encrypt files and directories
- **`unlock`** - Decrypt files and directories  
- **`cryptls`** - List encrypted files with original names
- **`cryptview`** - Securely view encrypted files
- **`cryptedit`** - Securely edit encrypted files

## Quick Start

```bash
# Build all tools
cargo build --release

# Encrypt a file (password prompted securely)
./target/release/lock secret.txt

# Encrypt with filename obfuscation
./target/release/lock --obfuscate secret.txt

# Encrypt and remove source file
./target/release/lock --remove-source secret.txt

# Decrypt a file (password prompted securely)
./target/release/unlock secret.txt.enc

# Decrypt and remove encrypted file  
./target/release/unlock --inplace secret.txt.enc

# List encrypted files in directory (password prompted securely)
./target/release/cryptls encrypted_files/

# View an encrypted file (Phase 10+)
./target/release/cryptview secret.txt.enc

# Edit an encrypted file (Phase 11+)
./target/release/cryptedit secret.txt.enc
```

## Status

This is a production-ready file encryption system with completed core features and comprehensive security audit. See [CHANGELOG.md](CHANGELOG.md) for version history and [ROADMAP.md](ROADMAP.md) for future plans.

**Security Status**: ✅ **Internal security audit completed** - No critical or high-risk vulnerabilities identified. Ready for external professional audit.

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design and module structure
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and progress tracking  
- **[ROADMAP.md](ROADMAP.md)** - Development roadmap and planned features
- **[SECURITY_AUDIT.md](../SECURITY_AUDIT.md)** - Comprehensive security audit report
- **[specs/](specs/)** - Detailed technical specifications

## Contributing

See [ROADMAP.md](ROADMAP.md) for development phases and contribution opportunities.

## Development

```bash
# Build all tools
cargo build --release

# Run all tests
cargo test

# Run specific tool with help
cargo run --bin lock -- --help
cargo run --bin unlock -- --help
cargo run --bin cryptls -- --help
```

## License

MIT OR Apache-2.0

## Contributing

See [ROADMAP.md](ROADMAP.md) for planned features and implementation phases.