# 🔐 Crypto File Encryptor

A high-security, high-performance file encryption program written in Rust, implementing the comprehensive design specification with advanced features and military-grade security.

## 🔧 Features

### Core Encryption
- **AES-256-CBC + HMAC-SHA256**: Military-grade encryption with authenticated encryption
- **Argon2id Key Derivation**: Memory-hard key derivation resistant to GPU attacks
- **Per-file Salt & IV**: Each file gets unique cryptographic parameters
- **Atomic Operations**: Safe file operations with rollback capability

### Advanced Features
- **Filename Obfuscation**: Collision-resistant, reversible filename encryption
- **Directory Structure Preservation**: Maintains original directory hierarchy
- **Partial Decryption**: View/edit files without full decryption
- **In-place Text Editing**: Edit encrypted text files with your favorite editor
- **File Previewing**: Preview file contents without full decryption
- **Metadata Preservation**: Maintains file permissions and timestamps

### Security Features
- **Dependency Inversion Principle**: Modular, testable architecture
- **Constant-time Operations**: Protection against timing attacks
- **Secure Memory Handling**: Automatic zeroization of sensitive data
- **Session Key Caching**: Performance optimization with security in mind
- **Parallel Processing**: Multi-threaded operations for large datasets

## 🚀 Installation

```bash
# Clone the repository
git clone <repository-url>
cd crypto

# Build the project
cargo build --release

# Install globally (optional)
cargo install --path .
```

## 📖 Usage

### Basic Commands

#### Encrypt a Single File
```bash
crypto encrypt-file -i document.pdf -o document.pdf.enc
```

#### Decrypt a Single File
```bash
crypto decrypt-file -i document.pdf.enc -o document.pdf
```

#### Encrypt a Directory
```bash
crypto encrypt-dir -i /path/to/folder -o /path/to/encrypted --recursive
```

#### Decrypt a Directory
```bash
crypto decrypt-dir -i /path/to/encrypted -o /path/to/decrypted --restore-structure
```

### Advanced Features

#### List Encrypted Files
```bash
# Basic listing
crypto list -d /path/to/encrypted

# Detailed listing with metadata
crypto list -d /path/to/encrypted --detailed
```

#### Edit Encrypted Text Files
```bash
# Edit with default editor (nano)
crypto edit -f secret.txt.enc

# Edit with specific editor
crypto edit -f secret.txt.enc -e vim
```

#### View Encrypted Files
```bash
# View with default viewer (less)
crypto view -f document.txt.enc

# Preview first 1024 bytes
crypto view -f document.txt.enc --preview 1024

# View with specific viewer
crypto view -f document.txt.enc --viewer cat
```

### Command Line Options

```bash
# Get help for any command
crypto --help
crypto encrypt-file --help

# Use password from command line (not recommended for security)
crypto encrypt-file -i file.txt -o file.txt.enc -p "password"

# Interactive password prompt (recommended)
crypto encrypt-file -i file.txt -o file.txt.enc
```

## 🏗️ Architecture

The project follows the **Dependency Inversion Principle (DIP)** for maximum modularity and testability:

### Core Traits (Abstractions)
- `KeyDeriver`: Key derivation operations
- `Encryptor`: Encryption/decryption operations  
- `FileSystem`: File system operations
- `PartialDecryptor`: Partial decryption capabilities
- `FileEditor`: In-place file editing
- `FileViewer`: File viewing and previewing
- `FileLister`: Encrypted file listing

### Concrete Implementations
- `Argon2KeyDeriver`: Argon2id-based key derivation
- `AesHmacEncryptor`: AES-256-CBC + HMAC-SHA256 encryption
- `StdFileSystem`: Standard filesystem operations
- `AdvancedFeatures`: Combined advanced functionality
- `EncryptionService`: Main orchestration service

### Module Structure
```
src/
├── lib.rs              # Library entry point
├── main.rs             # CLI entry point
├── error.rs            # Error types
├── types.rs            # Data structures
├── traits.rs           # Core trait definitions
├── crypto/             # Cryptographic implementations
│   ├── mod.rs
│   ├── key_derivation.rs
│   ├── encryption.rs
│   └── obfuscation.rs
├── filesystem/         # File system operations
│   ├── mod.rs
│   └── std_filesystem.rs
├── service/            # Business logic services
│   ├── mod.rs
│   ├── encryption_service.rs
│   ├── session_cache.rs
│   └── advanced_features.rs
└── cli/                # Command line interface
    ├── mod.rs
    ├── commands.rs
    └── app.rs
```

## 🔒 Security Features

### Cryptographic Security
- **AES-256-CBC**: Industry standard symmetric encryption
- **HMAC-SHA256**: Message authentication for integrity
- **Argon2id**: Memory-hard key derivation (64 MiB, t=3, p=4)
- **Cryptographically Secure RNG**: For salt and IV generation

### Implementation Security
- **Constant-time Operations**: All HMAC comparisons use constant-time functions
- **Automatic Zeroization**: Sensitive data automatically cleared from memory
- **Side-channel Mitigation**: Protection against timing attacks
- **Error Uniformity**: All authentication failures return identical errors

### File Header Format
```
[Magic: 4 bytes = "ENC2"]
[Version: 2 bytes = 2]
[Salt: 16 bytes]
[IV: 16 bytes]
[Directory Path Length: 2 bytes]
[Encrypted Directory Path: variable]
[Directory Path HMAC: 32 bytes]
[Filename Length: 2 bytes]
[Encrypted Filename: variable length]
[Filename HMAC: 32 bytes]
[Metadata Length: 2 bytes]
[Encrypted Metadata: variable]
[Metadata HMAC: 32 bytes]
[Encrypted Content: variable length]
[Content HMAC: 32 bytes]
```

## ⚡ Performance

### Optimizations
- **Streaming I/O**: Efficient handling of large files
- **Parallel Processing**: Multi-threaded directory encryption
- **Session Key Caching**: Reduces key derivation overhead
- **Optimal Buffering**: 64KB buffers for I/O operations
- **Hardware Acceleration**: Utilizes AES-NI when available

### Benchmarks
Performance testing can be run with:
```bash
cargo test --release
```

## 🧪 Testing

### Running Tests
```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test module
cargo test crypto::tests

# Run integration tests
cargo test --test integration
```

### Test Categories
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Property Tests**: Randomized testing with proptest
- **Security Tests**: Cryptographic correctness verification

## 🔧 Development

### Prerequisites
- Rust 1.70.0 or later
- Cargo

### Dependencies
- `aes`, `cbc`: AES encryption
- `hmac`, `sha2`: HMAC authentication  
- `argon2`: Key derivation
- `secrecy`: Secure memory handling
- `rayon`: Parallel processing
- `clap`: Command line interface
- `tempfile`: Temporary file handling
- `base64`: Base64 encoding
- `serde`, `bincode`: Serialization

### Building from Source
```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# With all features
cargo build --all-features
```

## 📝 Examples

### Batch Encryption Script
```bash
#!/bin/bash
# Encrypt all files in a directory
find /path/to/documents -type f -name "*.txt" | while read file; do
    crypto encrypt-file -i "$file" -o "${file}.enc"
done
```

### Backup Script with Encryption
```bash
#!/bin/bash
# Create encrypted backup
tar czf - /important/data | crypto encrypt-file -i - -o backup-$(date +%Y%m%d).tar.gz.enc
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 References

- [AES-256 Specification](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
- [HMAC-SHA256 RFC](https://tools.ietf.org/html/rfc2104)
- [Argon2id Specification](https://tools.ietf.org/html/rfc9106)
- [Rust Cryptography Guidelines](https://github.com/RustCrypto)

## ⚠️ Security Notice

This implementation is for educational and demonstration purposes. For production use, please have the code audited by security professionals and ensure compliance with your organization's security requirements.
