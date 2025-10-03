# Shadow - High-Security File Encryption Suite

**Professional-grade cryptographic file protection with multiple algorithm support and format versioning.**

## Overview

Shadow provides military-grade file encryption with modern cryptographic algorithms, featuring:

- **🔒 Dual Algorithm Support**: XChaCha20-Poly1305 (default) and AES-256-GCM
- **🛡️ Format Versioning**: Future-proof V2 format with migration support  
- **⚡ High Performance**: Optimized for both security and speed
- **🎯 Multiple Use Cases**: Single files, batch operations, secure viewing, and editing
- **🔧 Developer Friendly**: Comprehensive API with trait-based configuration

## Quick Start

### Installation
```bash
cargo install shadow-crypt
```

### Basic Usage
```bash
# Encrypt a file (uses XChaCha20-Poly1305 by default)
shadow encrypt document.txt

# Decrypt a file  
shadow decrypt document.txt.shadow

# List encrypted files in directory
shadows /path/to/encrypted/files

# View encrypted file without permanent decryption
shadowview document.txt.shadow
```

### Advanced Options
```bash
# Use AES-256-GCM algorithm
shadow encrypt --algorithm aes-gcm document.txt

# Batch encrypt with filename obfuscation
shadow encrypt --obfuscate *.txt

# Remove source files after encryption
shadow encrypt --remove-source *.txt
```

## Security Features

- **Post-Quantum Resistant**: XChaCha20-Poly1305 with extended nonce space
- **Authenticated Encryption**: Built-in tamper detection and data integrity
- **Secure Key Derivation**: Argon2id with adaptive parameters
- **Memory Protection**: Automatic zeroization of sensitive data
- **Timing Attack Resistance**: Constant-time operations where applicable

## Documentation

For comprehensive usage, API reference, and security details:
- [User Guide](docs/) - Complete usage documentation
- [API Reference](https://docs.rs/shadow-crypt) - Developer documentation
- [Security Model](docs/SECURITY.md) - Cryptographic specifications

## License

Licensed under either of Apache License 2.0 or MIT License at your option.