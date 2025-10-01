# Vertical Slicing Architecture Specification

## Overview

This document specifies the vertical slicing architecture for the Shadow file encryption system, addressing customer feedback about organizing code by version and algorithm for better maintainability and extensibility.

## Current Architecture Issues

### Problems Identified
1. **Mixed Concerns**: `shared/` module mixes version-specific, algorithm-specific, and truly shared code
2. **Tight Coupling**: Changes to version logic can affect algorithm code and vice versa
3. **Future Complexity**: Adding new versions or algorithms requires touching existing code
4. **Unclear Ownership**: Hard to determine which code belongs to which version/algorithm

### Impact of Current Structure
- Difficult to add Version 2 without affecting Version 1 code
- Algorithm changes affect all versions unnecessarily  
- Shared utilities mixed with domain-specific logic
- Import dependencies create circular complexity

## Target Architecture

### Organizational Principles
1. **Vertical Slicing**: Each version and algorithm gets its own complete module
2. **Horizontal Sharing**: Truly shared utilities in dedicated core modules
3. **Clear Boundaries**: No cross-dependencies between versions or algorithms
4. **Minimal Interfaces**: Clean public APIs with minimal surface area

### Module Hierarchy

```
src/shared/
├── core/                           # Truly shared utilities
│   ├── errors.rs                   # Error types (used everywhere)
│   ├── file_detection.rs           # File type detection utilities
│   ├── secure_delete.rs            # Security utilities  
│   ├── crypto/                     # Core cryptographic primitives
│   │   ├── nonce_tracking.rs       # Global nonce collision detection
│   │   ├── timing_analysis.rs      # Timing attack detection
│   │   ├── secure_memory.rs        # SecretVec and memory protection
│   │   └── mod.rs
│   └── mod.rs
├── versions/                       # Version-specific implementations
│   ├── v1/                         # Shadow format version 1
│   │   ├── header.rs               # V1 header structure and serialization
│   │   ├── format.rs               # V1-specific format operations
│   │   ├── crypto.rs               # V1 crypto integration (uses algorithms/)
│   │   └── mod.rs                  # V1 public interface
│   ├── v2/                         # Future: Shadow format version 2  
│   │   ├── header.rs               # V2 header (different structure)
│   │   ├── format.rs               # V2 format operations
│   │   ├── crypto.rs               # V2 crypto integration
│   │   └── mod.rs
│   ├── detection.rs                # Version detection from file headers
│   ├── dispatch.rs                 # Runtime version dispatch
│   └── mod.rs                      # Version management interface
├── algorithms/                     # Algorithm-specific implementations
│   ├── aes_gcm/                    # AES-256-GCM implementation
│   │   ├── encryption.rs           # AES-GCM encryption operations
│   │   ├── decryption.rs           # AES-GCM decryption operations
│   │   ├── key_derivation.rs       # Argon2 integration for AES
│   │   └── mod.rs                  # AES-GCM interface
│   ├── chacha20_poly1305/          # Future algorithm
│   │   ├── encryption.rs
│   │   ├── decryption.rs  
│   │   ├── key_derivation.rs
│   │   └── mod.rs
│   ├── kyber_aes256/               # Future post-quantum
│   │   └── ...
│   ├── selection.rs                # Algorithm selection logic
│   ├── registry.rs                 # Algorithm capability registry
│   └── mod.rs                      # Algorithm management interface
├── metadata.rs                     # File metadata (shared across versions)
├── filename_auth.rs                # Filename authentication (current utility)
├── header.rs                       # Unified header interface (dispatch layer)
└── mod.rs                          # Main shared module interface
```

## Implementation Benefits

### For Developers
- **Clear Ownership**: Each feature has an obvious home
- **Independent Development**: Work on V2 without touching V1 code
- **Easy Testing**: Version and algorithm logic can be tested in isolation
- **Reduced Conflicts**: Parallel development with minimal merge conflicts

### For Maintainability  
- **Focused Changes**: Algorithm improvements don't affect version logic
- **Clear Dependencies**: Import structure shows actual relationships
- **Easier Debugging**: Problems localized to specific modules
- **Documentation**: Architecture self-documents through structure

### For Extensibility
- **New Versions**: Add `versions/v3/` without touching existing code
- **New Algorithms**: Add `algorithms/quantum_resistant/` independently  
- **Feature Flags**: Easy to enable/disable versions or algorithms
- **Migration**: Clear upgrade paths between versions

## Migration Strategy

### Phase 1: Core Utilities Extraction (9.94.2)
1. Move truly shared code to `core/` modules
2. Update imports in existing code to use `core::` paths
3. Validate no functionality changes

### Phase 2: Version Separation (9.94.3)  
1. Create `versions/v1/` with current version-specific code
2. Update version detection and dispatch
3. Maintain backward compatibility in public APIs

### Phase 3: Algorithm Separation (9.94.4)
1. Create `algorithms/aes_gcm/` with current algorithm code
2. Create algorithm selection and registry system
3. Update crypto operations to use algorithm modules

### Phase 4: Integration and Cleanup (9.94.5)
1. Update all imports throughout codebase
2. Create unified public interfaces
3. Remove old modules and update documentation
4. Comprehensive testing and validation

## API Design Principles

### Version Interface
```rust
// Each version provides a consistent interface
pub trait VersionHandler {
    type Header: HeaderTrait;
    
    fn create_header(algorithm: AlgorithmId, salt: [u8; 16], nonce: [u8; 12]) -> Self::Header;
    fn parse_header(data: &[u8]) -> Result<(Self::Header, usize), CryptoError>;
    fn encrypt_file(&self, input: &Path, output: &Path, options: &EncryptOptions) -> Result<(), CryptoError>;
    fn decrypt_file(&self, input: &Path, output: &Path, options: &DecryptOptions) -> Result<(), CryptoError>;
}
```

### Algorithm Interface  
```rust
// Each algorithm provides consistent crypto operations
pub trait Algorithm {
    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn generate_key() -> [u8; 32];
    fn generate_nonce() -> Result<[u8; 12], CryptoError>;
    fn key_size() -> usize;
    fn nonce_size() -> usize;
}
```

### Unified Public Interface
```rust
// Top-level interface remains simple and backward compatible
pub fn encrypt_file(input: &Path, output: &Path, password: &str, options: &EncryptOptions) -> Result<(), CryptoError>;
pub fn decrypt_file(input: &Path, output: &Path, password: &str, options: &DecryptOptions) -> Result<(), CryptoError>;
pub fn list_files(directory: &Path, password: &str) -> Result<Vec<FileInfo>, CryptoError>;
```

## Risk Assessment

### Low Risk Elements
- **Core utilities extraction**: Well-defined boundaries, minimal dependencies
- **Version 1 encapsulation**: Existing code just moves to new location
- **Algorithm abstraction**: Current AES-GCM code is already well-contained

### Medium Risk Elements  
- **Import path updates**: Extensive but mechanical changes across codebase
- **Public API preservation**: Need to ensure no breaking changes for users
- **Testing coverage**: Must verify all functionality during migration

### High Risk Elements
- **Cross-module dependencies**: Potential circular dependencies during transition
- **Performance impact**: Additional indirection layers could affect performance
- **Integration complexity**: Coordinating changes across multiple modules

### Mitigation Strategies
1. **Incremental Migration**: Small, testable steps with rollback capability
2. **Extensive Testing**: Full test suite after each phase
3. **Backward Compatibility**: Maintain existing APIs throughout migration
4. **Performance Monitoring**: Benchmark critical paths during changes

## Success Criteria

### Functional Requirements
- ✅ All existing functionality preserved
- ✅ All 129 tests continue passing
- ✅ No performance regression in critical paths
- ✅ Backward compatibility maintained

### Architectural Requirements  
- ✅ Clear separation of concerns (version vs algorithm vs core)
- ✅ No circular dependencies between modules
- ✅ Easy to add new versions without touching existing code
- ✅ Easy to add new algorithms without touching existing code

### Documentation Requirements
- ✅ Updated architecture documentation
- ✅ Clear module responsibility definitions
- ✅ Migration guide for future developers
- ✅ API documentation reflects new structure

## Timeline and Dependencies

### Prerequisites
- Phase 9.93 ✅ Complete (filename authentication working)
- Current codebase ✅ Stable (all tests passing)
- Architecture specification ✅ Approved

### Estimated Duration
- **Phase 9.94.2**: Core extraction (1-2 days)
- **Phase 9.94.3**: Version separation (1-2 days)  
- **Phase 9.94.4**: Algorithm separation (1-2 days)
- **Phase 9.94.5**: Integration and cleanup (1 day)
- **Total**: 4-7 days depending on complexity

### Next Steps
1. **Review and approve** this specification
2. **Begin Phase 9.94.2** with core utilities extraction
3. **Validate approach** with first phase before proceeding
4. **Adjust timeline** based on lessons learned

## Future Extensibility Examples

### Adding Version 2
```rust
// Simply add new module - no existing code changes
src/shared/versions/v2/
├── header.rs           # New V2 header format  
├── format.rs           # V2-specific operations
├── crypto.rs           # V2 crypto integration
└── mod.rs              # V2 interface implementation
```

### Adding ChaCha20-Poly1305
```rust  
// Add new algorithm - no existing code changes
src/shared/algorithms/chacha20_poly1305/
├── encryption.rs       # ChaCha20 encryption
├── decryption.rs       # ChaCha20 decryption
├── key_derivation.rs   # ChaCha20 key handling
└── mod.rs              # Algorithm interface impl
```

### Adding Post-Quantum Cryptography
```rust
// Future-ready for post-quantum algorithms
src/shared/algorithms/kyber_aes256/
├── key_encapsulation.rs    # CRYSTALS-Kyber KEM
├── symmetric_crypto.rs     # AES-256-GCM for bulk data
├── key_derivation.rs       # Hybrid key derivation
└── mod.rs                  # Algorithm interface impl
```

This architecture ensures that the Shadow encryption system can evolve cleanly and maintainably over time while preserving all existing functionality and security properties.