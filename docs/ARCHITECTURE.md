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

## Module Structure ✅ **IMPLEMENTED**

```
src/
├── lib.rs                     // ✅ Public API for shared functionality
├── shared/                    // ✅ Core shared components
│   ├── mod.rs                 // ✅ Module exports and re-exports
│   ├── crypto/                // ✅ Cryptographic primitives
│   │   ├── mod.rs             // ✅ Crypto module exports
│   │   ├── aes.rs             // ✅ AES-GCM implementation (placeholder)
│   │   ├── argon2.rs          // ✅ Argon2 key derivation (placeholder)
│   │   └── secure_memory.rs   // ✅ SecretVec and secure memory handling
│   ├── header.rs              // ✅ File header format with serialization
│   ├── file_detection.rs      // ✅ Detect encrypted files by magic number
│   └── errors.rs              // ✅ Comprehensive error types
├── encryption/                // ✅ Everything needed for lock binary
│   ├── mod.rs                 // ✅ Encryption module exports
│   ├── encrypt_file.rs        // ✅ Single file encryption (placeholder)
│   ├── encrypt_directory.rs   // ✅ Directory encryption (placeholder)
│   ├── filename_obfuscation.rs// ✅ Filename obfuscation (placeholder)
│   └── cli.rs                 // ✅ CLI interface (placeholder)
├── decryption/                // ✅ Everything needed for unlock binary
│   ├── mod.rs                 // ✅ Decryption module exports
│   ├── decrypt_file.rs        // ✅ Single file decryption (placeholder)
│   ├── decrypt_directory.rs   // ✅ Directory decryption (placeholder)
│   ├── filename_restoration.rs// ✅ Filename restoration (placeholder)
│   └── cli.rs                 // ✅ CLI interface (placeholder)
├── listing/                   // ✅ Everything needed for cryptls binary
│   ├── mod.rs                 // ✅ Listing module exports
│   ├── file_scanner.rs        // ✅ File scanning (placeholder)
│   ├── metadata_extractor.rs  // ✅ Metadata extraction (placeholder)
│   └── cli.rs                 // ✅ CLI interface (placeholder)
├── viewing/                   // ✅ Everything needed for cryptview binary
│   ├── mod.rs                 // ✅ Viewing module exports
│   ├── viewer_integration.rs  // ✅ Viewer integration (placeholder)
│   ├── streaming_decrypt.rs   // ✅ Streaming decryption (placeholder)
│   └── cli.rs                 // ✅ CLI interface (placeholder)
├── editing/                   // ✅ Everything needed for cryptedit binary
│   ├── mod.rs                 // ✅ Editing module exports
│   ├── editor_integration.rs  // ✅ Editor integration (placeholder)
│   ├── atomic_updates.rs      // ✅ Atomic updates (placeholder)
│   └── cli.rs                 // ✅ CLI interface (placeholder)
└── bin/                       // ✅ Binary entry points
    ├── lock.rs                // ✅ use crate::encryption
    ├── unlock.rs              // ✅ use crate::decryption
    ├── cryptls.rs             // ✅ use crate::listing
    ├── cryptview.rs           // ✅ use crate::viewing
    └── cryptedit.rs           // ✅ use crate::editing
```

**Implementation Notes:**
- All modules compile cleanly with proper trait bounds
- Placeholder implementations are marked with TODO comments and phase numbers
- Error handling is consistent across all modules
- SecretVec implements proper zeroization with Clone and Debug traits
- Binary targets are configured in Cargo.toml for all five tools

## Dependency Architecture

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   lock      │  │   unlock    │  │  cryptls    │
│   binary    │  │   binary    │  │   binary    │
└─────────────┘  └─────────────┘  └─────────────┘
       │                │                │
       ▼                ▼                ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ encryption/ │  │ decryption/ │  │  listing/   │
│   module    │  │   module    │  │   module    │
└─────────────┘  └─────────────┘  └─────────────┘
       │                │                │
       └────────────────┼────────────────┘
                        ▼
                ┌─────────────┐
                │   shared/   │
                │   module    │
                └─────────────┘
```

## Benefits of This Architecture

### Feature-Complete Modules

Each module contains everything needed for its use case:
- Business logic
- File I/O operations  
- CLI handling
- Specific error handling

### Independent Development

- Work on `lock` without touching `unlock` code
- Add new features to `cryptview` without affecting other binaries
- Deploy/update binaries independently
- Clear feature ownership

### Optimized Compilation

- Each binary only compiles what it needs
- Faster build times
- Smaller binary sizes
- Reduced dependencies per tool

### Clear Ownership

- Each feature has a clear "home"
- No confusion about where code belongs
- Easy reasoning about dependencies
- Simplified testing and maintenance

## Core Shared Components

### Cryptographic Primitives (`shared/crypto/`)

- **AES-GCM encryption** with proper nonce handling
- **Argon2id key derivation** with adaptive parameters
- **Secure memory abstractions** with automatic zeroization
- **Hardware acceleration** support where available

### File Format (`shared/header.rs`)

- **Magic number detection** ("ENC3")
- **Algorithm identifiers** for cryptographic agility
- **Serialization/deserialization** with proper padding
- **Metadata storage** with authentication

### Error Handling (`shared/errors.rs`)

- **Comprehensive error types** covering all failure modes
- **Proper error chaining** with source information
- **Consistent error messages** across all modules
- **Security-conscious error handling** (no information leakage)

## Phase 1 Implementation Achievements ✅

**Module Structure**: Complete vertical slicing architecture implemented exactly as designed with all directories, files, and module exports in place.

**Error Handling**: Comprehensive `CryptoError` enum with proper error chaining and `From` trait implementations for seamless error propagation.

**Secure Memory**: `SecretVec<T>` implementation with automatic zeroization, proper trait bounds (`Clone`, `Debug`), and memory protection abstractions.

**Header Format**: Complete `Header` struct with serialization/deserialization methods, algorithm agility support, and magic number validation.

**File Detection**: Utility functions for detecting encrypted files by magic number and parsing headers without full decryption.

**Binary Configuration**: All five binaries (`lock`, `unlock`, `cryptls`, `cryptview`, `cryptedit`) configured in Cargo.toml with proper entry points.

**Compilation Success**: All code compiles cleanly with no warnings or errors, ready for cryptographic implementation in Phase 2.

## Next Steps

See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for current progress and [ROADMAP.md](ROADMAP.md) for detailed implementation phases.