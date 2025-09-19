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

# Encrypt a file
./target/release/lock secret.txt secret.txt.enc mypassword123

# Decrypt a file  
./target/release/unlock secret.txt.enc

# List encrypted files in directory (Phases 8+)
./target/release/cryptls encrypted_files/ mypassword123

# View an encrypted file (Phase 9+)
./target/release/cryptview secret.txt.enc

# Edit an encrypted file (Phase 10+)
./target/release/cryptedit secret.txt.enc
```

## Implementation Status

- ✅ **Phase 1**: Module structure and architecture foundation
- ✅ **Phase 2**: Header implementation with complete serialization
- ✅ **Phase 3**: Core cryptographic operations
- ✅ **Phase 4**: Basic file encryption
- ✅ **Phase 5**: Basic file decryption
- ✅ **Phase 6**: Filename obfuscation
- ✅ **Phase 7**: Filename restoration
- ✅ **Phase 8**: File listing capability
- 🚧 **Phase 9**: Directory encryption (Next)
- ⏳ **Phases 10-20**: Feature implementation and optimization

### Current Capabilities (Phases 1-8 Complete)

✅ **Working Features:**
- Single file encryption with AES-256-GCM
- Password-based key derivation using Argon2id  
- File metadata preservation (permissions, timestamps)
- Complete file decryption with integrity verification
- Secure filename obfuscation with collision resistance
- Intelligent filename restoration during decryption
- Cross-platform command-line tools (`lock`, `unlock`, and `cryptls`)
- Directory scanning and encrypted file listing
- Original filename display without full decryption
- Comprehensive test coverage and validation

🚧 **In Development:**
- Directory encryption and batch processing
- File viewing and editing tools
- Advanced CLI features and user experience improvements

See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for detailed progress.

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and module structure
- **[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)** - Current progress and next steps  
- **[ROADMAP.md](ROADMAP.md)** - Complete implementation roadmap
- **[specs/](specs/)** - Detailed technical specifications

## Security

This system implements industry-leading security practices:

- **No padding oracle vulnerabilities** (AES-GCM vs CBC+HMAC)
- **Per-file salts** and secure nonce generation
- **Adaptive Argon2id** key derivation (256MB-1GB memory)
- **Secure memory handling** with mlock() and zeroization
- **Constant-time operations** and side-channel mitigation

See [specs/security.md](specs/security.md) for detailed security analysis.

## Architecture

The system uses **vertical slicing by use case** - each tool is self-contained with its own module, sharing common cryptographic primitives through a library.

```
├── shared/           # Common cryptographic primitives
├── encryption/       # Everything for 'lock' binary
├── decryption/       # Everything for 'unlock' binary  
├── listing/          # Everything for 'cryptls' binary
├── viewing/          # Everything for 'cryptview' binary
├── editing/          # Everything for 'cryptedit' binary
└── bin/              # Binary entry points
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for complete details.

## Development

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --test decryption_integration

# Check code quality
cargo check

# Build and run specific tool
cargo run --bin lock -- input.txt output.enc password123
cargo run --bin unlock -- output.enc decrypted.txt

# Run with help
cargo run --bin lock -- --help
cargo run --bin unlock -- --help
```

### Current Tools Status

- ✅ **`lock`** - Fully functional file encryption
- ✅ **`unlock`** - Fully functional file decryption
- 🚧 **`cryptls`** - Placeholder (Phase 6+)
- 🚧 **`cryptview`** - Placeholder (Phase 8+)  
- 🚧 **`cryptedit`** - Placeholder (Phase 9+)

## License

MIT OR Apache-2.0

## Contributing

See [ROADMAP.md](ROADMAP.md) for planned features and implementation phases.