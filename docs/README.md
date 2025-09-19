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
./target/release/lock --obfuscate secret.txt

# Decrypt a file  
./target/release/unlock secret.txt.enc

# List encrypted files in directory
./target/release/cryptls encrypted_files/

# View an encrypted file
./target/release/cryptview secret.txt.enc

# Edit an encrypted file
./target/release/cryptedit secret.txt.enc
```

## Implementation Status

- ✅ **Phase 1**: Module structure and architecture foundation
- ✅ **Phase 2**: Header implementation with complete serialization
- ✅ **Phase 3**: Core cryptographic operations
- 🚧 **Phase 4**: Basic file encryption (Next)
- ⏳ **Phases 5-20**: Feature implementation and optimization

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
# Run tests
cargo test

# Check code
cargo check

# Run specific tool
cargo run --bin lock -- --help
cargo run --bin unlock -- --help
cargo run --bin cryptls -- --help
cargo run --bin cryptview -- --help  
cargo run --bin cryptedit -- --help
```

## License

MIT OR Apache-2.0

## Contributing

See [ROADMAP.md](ROADMAP.md) for planned features and implementation phases.