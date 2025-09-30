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
./target/release/lock secret.txt secret.txt.enc

# Encrypt with filename obfuscation (output filename optional)
./target/release/lock --obfuscate secret.txt

# Decrypt a file (password prompted securely)
./target/release/unlock secret.txt.enc

# List encrypted files in directory (password prompted securely)
./target/release/cryptls encrypted_files/

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
- ✅ **User Feedback Integration**: Security and UX improvements
- ✅ **Phase 8.5**: Critical UX fixes (**COMPLETED** - Enhanced display and file safety)
- 🚧 **Phase 9**: Source file removal support (**CURRENT PRIORITY** - User feedback: more important than multi-file)
- ⏳ **Phase 10**: Multi-file encryption support (**REPRIORITIZED**)
- ⏳ **Phase 11**: Multi-file decryption support (**REPRIORITIZED**)
- ⏳ **Phase 11.5**: Security audit (**NEW** - User requested ASAP)
- ⏳ **Phases 12-20**: Advanced features and optimization

### Current Capabilities (Phases 1-8.5 Complete)

✅ **Working Features:**
- Single file encryption with AES-256-GCM
- **Secure password input** (no command-line password exposure)
- **Simplified filename obfuscation workflow** (output filename optional)
- Password-based key derivation using Argon2id  
- File metadata preservation (permissions, timestamps)
- Complete file decryption with integrity verification
- Secure filename obfuscation with collision resistance
- Intelligent filename restoration during decryption
- Cross-platform command-line tools (`lock`, `unlock`, and `cryptls`)
- **Enhanced directory scanning** with encrypted file listing
- **Enhanced `cryptls` display** showing both obfuscated and original filenames with clear mapping
- **File overwrite protection** with `--force` flag requirement for intentional overwrites
- Comprehensive test coverage and validation

🚧 **In Development (Phase 9):**
- Source file removal support with `--remove-source`/`--inplace` flags (focus area per user feedback)
- Enhanced single-file workflow with secure source deletion

⏳ **Next Priorities:**
- Multi-file encryption and batch processing (Phase 10+)
- File viewing and editing tools
- Advanced CLI features and user experience improvements

⏸️ **Postponed (Per User Feedback):**
- Directory encryption (postponed to focus on single/multi-file support)

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