# Architecture Overview

This document provides a comprehensive overview of the Shadow file encryption system architecture, including the vertical slicing design that enables clean separation of concerns and extensibility.

## Core Design Philosophy

### Security-First Architecture
All architectural decisions prioritize security and cryptographic best practices:

- **Authenticated Encryption**: AES-256-GCM eliminates padding oracle vulnerabilities
- **Secure Memory Handling**: Automatic zeroization prevents key recovery from memory
- **Cryptographic Agility**: Plugin architecture enables future algorithm upgrades
- **Side-Channel Mitigation**: Timing analysis and entropy validation throughout
- **Defense in Depth**: Multiple layers of security controls

### Vertical Slicing with Horizontal Sharing
The system uses vertical slicing by use case and file format version, with horizontal sharing of truly common utilities:

- **Independent Development**: Each tool and version can evolve independently
- **Clear Ownership**: Distinct modules with well-defined responsibilities  
- **Optimized Compilation**: Clean dependencies enable efficient builds
- **Easy Extension**: New versions and algorithms require minimal existing code changes

## System Overview

### Command-Line Tools (Vertical Slices)
```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   shadow    │  │  unshadow   │  │   shadows   │  │ shadowview  │  │ shadowedit  │  │shadowmigrate│
│  (encrypt)  │  │  (decrypt)  │  │   (list)    │  │   (view)    │  │   (edit)    │  │ (migrate)   │
└─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
       │                │                │                │                │                │
       ▼                ▼                ▼                ▼                ▼                ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ encryption/ │  │ decryption/ │  │  listing/   │  │  viewing/   │  │  editing/   │  │ migration/  │
│   module    │  │   module    │  │   module    │  │   module    │  │   module    │  │   module    │
└─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
       │                │                │                │                │                │
       └────────────────┼────────────────┼────────────────┼────────────────┼────────────────┘
                        │                │                │                │
                        ▼                ▼                ▼                ▼
                ┌─────────────────────────────────────────────────────────────┐
                │                    shared/ library                         │
                └─────────────────────────────────────────────────────────────┘
```

### Shared Library Architecture (Horizontal Layers)

The shared library implements clean vertical slicing with horizontal sharing:

```
src/shared/
├── core/                           # Truly shared utilities (no version/algorithm specifics)
│   ├── errors.rs                   # Error types used across all modules
│   ├── file_detection.rs           # Generic file type detection
│   ├── secure_delete.rs            # Security utilities for file operations
│   ├── crypto/                     # Core cryptographic primitives
│   │   ├── nonce_tracking.rs       # Global nonce collision detection
│   │   ├── timing_analysis.rs      # Timing attack detection and mitigation
│   │   ├── secure_memory.rs        # SecretVec and memory protection
│   │   └── mod.rs                  # Core crypto interface
│   └── mod.rs                      # Core utilities interface
├── versions/                       # Version-specific file format logic
│   ├── v1/                         # Shadow format version 1 implementation
│   │   ├── header.rs               # V1 header structure and serialization
│   │   ├── filename_auth.rs        # V1 filename authentication logic
│   │   ├── detection.rs            # V1 file detection logic
│   │   ├── dispatch.rs             # V1 operation dispatch
│   │   └── mod.rs                  # V1 public interface
│   ├── v2/                         # Future: Shadow format version 2
│   │   └── [Future implementation] # Will contain V2-specific logic
│   └── mod.rs                      # Version management interface
├── algorithms/                     # Algorithm-specific implementations
│   ├── aes_gcm/                    # AES-256-GCM with Argon2 key derivation
│   │   ├── encryption.rs           # AES-GCM encryption operations
│   │   ├── decryption.rs           # AES-GCM decryption operations  
│   │   ├── key_derivation.rs       # Argon2 key derivation for AES
│   │   └── mod.rs                  # AES-GCM interface
│   ├── chacha20/                   # Future: ChaCha20-Poly1305 implementation
│   │   └── [Future implementation] # Will contain ChaCha20 logic
│   ├── constants.rs                # Algorithm identifiers and version info
│   ├── selection.rs                # Algorithm selection logic
│   ├── registry.rs                 # Algorithm capability registration
│   └── mod.rs                      # Algorithm management interface
├── metadata.rs                     # File metadata handling
├── version_dispatch.rs             # Multi-version operation dispatch
├── versioning.rs                   # Version compatibility management
├── header.rs                       # Header abstraction interface
└── mod.rs                          # Shared library public interface
```

## Key Architectural Benefits

### 1. Clean Separation of Concerns

**Version Independence**: Each file format version is completely self-contained:
- V1 logic in `versions/v1/` doesn't affect future V2 development
- Version-specific operations (headers, authentication) isolated
- Easy to deprecate old versions without affecting others

**Algorithm Independence**: Each encryption algorithm is self-contained:
- AES-GCM implementation in `algorithms/aes_gcm/` 
- Future ChaCha20 can be added without touching AES code
- Algorithm-specific optimizations don't affect other algorithms

**Core Utilities Separation**: Truly shared code isolated in `core/`:
- Error handling used by all modules
- Security utilities (secure delete, memory protection)
- No version or algorithm-specific logic

### 2. Extensibility and Future-Proofing

**Easy Version Addition**: Adding Shadow file format V2:
1. Create `versions/v2/` module with V2-specific logic
2. Update `version_dispatch.rs` routing
3. No changes needed to V1 code or algorithms

**Easy Algorithm Addition**: Adding ChaCha20-Poly1305:
1. Create `algorithms/chacha20/` module  
2. Register in `algorithms/registry.rs`
3. No changes needed to AES-GCM or core code

**Migration Path**: Gradual migration between versions:
- `migration/` module provides analysis and conversion tools
- Version compatibility matrix enables partial upgrades
- Rollback capabilities for safety

### 3. Development and Maintenance Benefits

**Independent Development**: Teams can work on different versions/algorithms simultaneously without conflicts

**Clear Ownership**: Each module has well-defined responsibilities and interfaces

**Optimized Builds**: Clean dependencies enable:
- Faster compilation times
- Smaller binary sizes through dead code elimination
- Better optimization opportunities

**Testing Isolation**: Each module can be thoroughly tested independently

## Security Architecture

### Cryptographic Design

**Authenticated Encryption**: AES-256-GCM provides:
- Confidentiality through AES-256 encryption
- Integrity and authenticity through Galois Counter Mode
- Resistance to padding oracle attacks (no padding)

**Key Derivation**: Argon2 provides:
- Memory-hard key derivation resistant to GPU attacks
- Adaptive parameters based on system capabilities
- Salt-based derivation prevents rainbow table attacks

**Nonce Management**: Comprehensive nonce safety:
- Cryptographically secure random nonce generation
- Global nonce reuse detection and prevention
- Entropy validation to detect weak randomness

### Side-Channel Resistance

**Timing Attack Mitigation**: 
- Constant-time operations for sensitive comparisons
- Timing analysis detects potential vulnerabilities
- Password verification timing independence

**Memory Protection**:
- Automatic zeroization of sensitive data (`SecretVec`)
- Secure memory allocation where possible
- Prevention of key recovery from memory dumps

**File System Security**:
- Secure deletion with multiple overwrite passes
- Temporary file cleanup and protection
- Permission validation and enforcement

## Implementation Status

### Completed (Phase 9.94.6)

✅ **Vertical Slicing Architecture**: Complete 4-phase refactoring
- Core utilities extracted to `shared/core/`
- Version 1 logic isolated in `shared/versions/v1/`  
- AES-GCM algorithm encapsulated in `shared/algorithms/aes_gcm/`
- Backward compatibility maintained through strategic re-exports

✅ **Production Readiness**: 133 tests passing, zero warnings, optimized code quality

✅ **Extensibility Validation**: Successfully tested V2 and ChaCha20 addition capabilities

### Future Architecture Evolution

**Phase 10+**: User-facing feature development on stable architectural foundation
**Version 2**: Enhanced file format with additional security features
**Algorithm Expansion**: ChaCha20-Poly1305 and future post-quantum algorithms
**Performance Optimization**: Hardware acceleration and optimized algorithms

## API Design Principles

### Clean Interfaces
- Minimal public surface area for each module
- Clear input/output contracts with comprehensive error handling
- Version-agnostic APIs where possible

### Error Handling Strategy
- Comprehensive error taxonomy in `core/errors.rs`
- Graceful degradation where appropriate
- Security-focused error messages (no information leakage)

### Testing Strategy
- Unit tests for each module in isolation
- Integration tests for cross-module workflows
- Security tests for timing attacks and side channels
- Performance tests for regression detection

This architecture provides a solid foundation for secure, maintainable, and extensible file encryption while enabling rapid development of new features and capabilities.
                │  └─────────┘ └─────────┘ └─────────────┘    │
                │  ┌─────────────────┐ ┌─────────────────┐    │
                │  │ versioning.rs   │ │version_dispatch │    │
                │  │                 │ │.rs              │    │
                │  │ HeaderV1        │ │ AnyHeader       │    │
                │  │ VersionedHeader │ │ VersionMigrator │    │
                │  │ CompatMatrix    │ │ MigrationPlan   │    │
                │  └─────────────────┘ └─────────────────┘    │
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
│   ├── versioning.rs          // Version-specific header types and traits
│   ├── version_dispatch.rs    // Version detection and unified interface
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