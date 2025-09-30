# Architecture

This document describes the system architecture and module organization for the crypto file encryption system.

## Core Design Principles

### Vertical Slicing by Use Case

The codebase is organized around distinct binaries with vertical slicing by use case, sharing common functionality through a library. This approach optimizes for:

- **Independent development** of each tool
- **Focused functionality** per binary
- **Optimized compilation** and binary sizes
- **Clear feature ownership**

### Security-First Design

All architectural decisions prioritize security:

- **Authenticated encryption** (AES-256-GCM) eliminates padding oracle vulnerabilities
- **Secure memory handling** with automatic zeroization
- **Cryptographic agility** enables future algorithm upgrades
- **Side-channel mitigation** throughout the system

## System Overview

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│    lock     │  │   unlock    │  │  cryptls    │  │ cryptview   │  │ cryptedit   │
│  (encrypt)  │  │  (decrypt)  │  │   (list)    │  │   (view)    │  │   (edit)    │
└─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
       │                │                │                │                │
       ▼                ▼                ▼                ▼                ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ encryption/ │  │ decryption/ │  │  listing/   │  │  viewing/   │  │  editing/   │
│   module    │  │   module    │  │   module    │  │   module    │  │   module    │
└─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
       │                │                │                │                │
       └────────────────┼────────────────┼────────────────┼────────────────┘
                        │                │                │
                        ▼                ▼                ▼
                ┌─────────────────────────────────────────────┐
                │              shared/ module                │
                │  ┌─────────┐ ┌─────────┐ ┌─────────────┐    │
                │  │ crypto/ │ │header.rs│ │ errors.rs   │    │
                │  │         │ │         │ │             │    │
                │  │ aes.rs  │ │file_    │ │secure_      │    │
                │  │argon2.rs│ │detection│ │delete.rs    │    │
                │  │secure_  │ │.rs      │ │             │    │
                │  │memory.rs│ │         │ │             │    │
                │  └─────────┘ └─────────┘ └─────────────┘    │
                └─────────────────────────────────────────────┘
```

## Module Structure

The system follows a vertical slice architecture where each binary has its own module containing all necessary functionality:

```
src/
├── lib.rs                     // Public API for shared functionality
├── shared/                    // Core shared components
│   ├── crypto/                // Cryptographic primitives
│   │   ├── aes.rs             // AES-256-GCM implementation
│   │   ├── argon2.rs          // Argon2id key derivation
│   │   └── secure_memory.rs   // SecretVec and secure memory handling
│   ├── header.rs              // File header format with serialization
│   ├── file_detection.rs      // Detect encrypted files by magic number
│   ├── errors.rs              // Comprehensive error types
│   └── secure_delete.rs       // Secure file deletion
├── encryption/                // Lock binary functionality
│   ├── encrypt_file.rs        // File encryption logic
│   ├── filename_obfuscation.rs// Filename obfuscation
│   └── cli.rs                 // CLI interface
├── decryption/                // Unlock binary functionality
│   ├── decrypt_file.rs        // File decryption logic
│   ├── filename_restoration.rs// Filename restoration
│   └── cli.rs                 // CLI interface
├── listing/                   // Cryptls binary functionality
│   ├── file_scanner.rs        // File scanning
│   ├── metadata_extractor.rs  // Metadata extraction
│   └── cli.rs                 // CLI interface
├── viewing/                   // Cryptview binary functionality
│   ├── streaming_decrypt.rs   // Streaming decryption
│   ├── viewer_integration.rs  // External viewer integration
│   └── cli.rs                 // CLI interface
├── editing/                   // Cryptedit binary functionality
│   ├── atomic_updates.rs      // Atomic file updates
│   ├── editor_integration.rs  // External editor integration
│   └── cli.rs                 // CLI interface
└── bin/                       // Binary entry points
    ├── lock.rs                // Encryption binary
    ├── unlock.rs              // Decryption binary
    ├── cryptls.rs             // Listing binary
    ├── cryptview.rs           // Viewing binary
    └── cryptedit.rs           // Editing binary
```

## Architecture Benefits

### Feature-Complete Modules
Each module contains everything needed for its use case:
- Business logic and algorithms
- File I/O operations  
- CLI handling and user interaction
- Specific error handling and recovery

### Independent Development
- Work on encryption without affecting decryption code
- Add new features to specific tools without cross-contamination
- Deploy and update binaries independently
- Clear feature ownership and responsibility

### Optimized Performance
- Each binary only compiles what it needs
- Faster build times and smaller binary sizes
- Reduced runtime dependencies per tool
- Efficient resource utilization

## Core Shared Components

For detailed specifications, see the `docs/specs/` directory:

### Cryptographic Layer (`shared/crypto/`)
- **AES-256-GCM** for authenticated encryption (see `specs/cryptography.md`)
- **Argon2id** for password-based key derivation
- **Secure memory** abstractions with automatic zeroization
- **Hardware acceleration** support where available

### File Format (`shared/header.rs`)
- **Magic number** detection for encrypted files (see `specs/file-format.md`)
- **Algorithm identifiers** for cryptographic agility
- **Metadata storage** with integrity protection
- **Version handling** for future compatibility

### Security Infrastructure
- **Comprehensive error types** with proper information isolation (see `specs/security.md`)
- **Timing attack protection** using constant-time operations
- **Secure file deletion** with multiple overwrite passes
- **Memory protection** against swap and core dumps

## Implementation Status

The system is currently in **Phase 10** of development with core single-file operations complete and multi-file support in progress. See:

- `ROADMAP.md` - Detailed development phases and timeline
- `CHANGELOG.md` - Version history and completed features
- `specs/` directory - Technical specifications for each component

## References

- [Technical Specifications](specs/) - Detailed component specifications
- [Development Roadmap](ROADMAP.md) - Implementation phases and progress
- [Change History](CHANGELOG.md) - Version history and features
- [Project Overview](README.md) - Getting started and usage examples