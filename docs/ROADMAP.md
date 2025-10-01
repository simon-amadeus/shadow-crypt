# Implementation Roadmap

## 🎯 NEXT PRIORITIES (Work in Progress)

- ⚡ **Phase 9.94**: Shared Module Architecture Refactoring (**NEXT PRIORITY** - ARCHITECTURE foundation for future versions/algorithms)
- ⚡ **Phase 10**: Multi-file encryption support (**HIGH PRIORITY** - CORE user functionality)

## 📋 FUTURE PHASES (Planned Work)

- 📋 **Phase 11**: Multi-file decryption support
- 📋 **Phase 12**: Performance optimization
- 📋 **Phase 13**: Secure viewing (`cryptview`)
- 📋 **Phase 14**: Secure editing (`cryptedit`)
- 📋 **Phase 15**: Comprehensive testing
- 📋 **Phase 16**: Documentation and polish
- 📋 **Phase 17**: Release preparation

## 🔧 OPTIONAL ENHANCEMENTS (Post-Production)

- 📋 **Phase 9.95**: Secure memory and cleanup hardening (**OPTIONAL** - Good practice, not critical for end-user tool)

---

<!-- 
IMPORTANT FOR DEVELOPERS:
When a phase is completed:
1. Add detailed implementation notes to CHANGELOG.md
2. Remove the completed phase from this roadmap 
3. Keep only future work in this file
4. Move any useful implementation details to CHANGELOG.md

This keeps the roadmap focused on "what's next" rather than "what's done"
-->

## Phase 9.94: Shared Module Architecture Refactoring (NEXT PRIORITY)

**Goal**: Design and plan vertical slicing architecture for versions and algorithms to enable clean future expansion

**Rationale**: Customer feedback identified that current shared module mixes version-specific logic with general utilities. As we add more file format versions and cryptographic algorithms, we need better separation of concerns through vertical slicing.

**Phase 9.94.1: Architecture Design and Analysis** (CURRENT FOCUS)
- [x] **Customer feedback integration** - Analyzed need for vertical slicing architecture 
- [x] **Current code analysis** - Identified mixing of concerns in shared modules
- [x] **Impact assessment** - Determined this requires multi-phase approach due to extensive import changes
- [ ] **Design target architecture** - Create detailed module hierarchy specification
- [ ] **Migration strategy** - Plan incremental refactoring approach to avoid breaking changes
- [ ] **Testing strategy** - Ensure no functionality regression during refactoring

**Future Sub-phases** (9.94.2+):
- **Phase 9.94.2**: Incremental module extraction (version-specific code)
- **Phase 9.94.3**: Algorithm-specific module organization  
- **Phase 9.94.4**: Import path updates and validation
- **Phase 9.94.5**: Integration testing and cleanup

**Target Architecture** (Detailed Design Required):
```
shared/
├── core/                   // Truly shared utilities
│   ├── errors.rs           // Error types used across all versions/algorithms
│   ├── file_detection.rs   // File type detection utilities
│   ├── secure_delete.rs    // Security utilities
│   └── crypto/             // Core crypto primitives
├── versions/               // Version-specific implementations
│   ├── v1/                 // Version 1 specific code
│   │   ├── header.rs       // V1 header format and operations
│   │   ├── format.rs       // V1-specific format handling
│   │   └── mod.rs
│   ├── v2/                 // Future version 2
│   └── mod.rs              // Version dispatch and detection
├── algorithms/             // Algorithm-specific implementations  
│   ├── aes_gcm/           // AES-256-GCM implementation
│   │   ├── encryption.rs   // Algorithm-specific encryption
│   │   ├── decryption.rs   // Algorithm-specific decryption
│   │   └── mod.rs
│   ├── chacha20_poly1305/ // Future algorithm
│   └── mod.rs             // Algorithm selection and dispatch
└── mod.rs                 // Clean unified public API
```

**Dependencies**: Phase 9.93 ✅ (filename authentication complete)

**Estimated Duration**: 3-4 days (multi-phase approach)

**Success Criteria**:
- **Completed design specification** with detailed module hierarchy
- **Migration strategy** that preserves functionality at each step
- **Clear separation** between version-specific, algorithm-specific, and core shared code
- **Maintainable architecture** that supports easy addition of new versions/algorithms
- **No functionality regression** - all existing tests continue to pass
- **Updated documentation** reflecting new architecture

---

## Phase 10: Multi-File Encryption Support (HIGH PRIORITY)

**Goal**: Support encrypting multiple individual files (not directories)

**Tasks**:
- [ ] Add support for multiple file arguments to `shadow` binary
- [ ] Implement batch processing for multiple individual files
- [ ] Add progress indicators for multi-file operations
- [ ] Support glob patterns for file selection
- [ ] Enhance error handling for partial failures
- [ ] Add parallel processing for performance

**Dependencies**: All critical security phases complete ✅

**Estimated Duration**: 2-3 days

**Success Criteria**:
- Can encrypt multiple individual files in one command
- Progress feedback shows per-file and overall progress
- Robust error handling for individual file failures
- Source removal works safely for multi-file operations
- Performance scales well with file count

---

## Phase 9.95: Secure Memory and Cleanup Hardening (OPTIONAL)

**Goal**: Complete secure memory implementation for high-security environments

**Tasks**:
- [ ] **Memory protection against swapping** - Critical for high-security environments
- [ ] **Complete secure memory implementation** - Enhanced SecretVec functionality
- [ ] **Memory cleanup verification** - Comprehensive zeroization validation

**Dependencies**: Phase 9.94 ✅ (architectural refactoring complete)

**Estimated Duration**: 1-2 days

**Success Criteria**:
- Secure memory implementation completed for high-security scenarios
- All sensitive data properly cleared from memory
- Memory protection mechanisms prevent data exposure

---

### Phase 11: Multi-File Decryption Support

**Goal**: Support decrypting multiple individual files

**Tasks**:
- [ ] Add support for multiple file arguments to `unlock` binary
- [ ] Implement batch processing for multiple encrypted files
- [ ] Add automatic output path determination for batch operations
- [ ] Support wildcard/glob patterns for encrypted file selection
- [ ] Add progress indicators and error handling

**Dependencies**: Phase 10 ✅ (Multi-file encryption with core security hardening complete)

**Estimated Duration**: 2-3 days

**Success Criteria**:
- Can decrypt multiple files in one command
- Automatic filename restoration works for all files
- Progress feedback and error handling work correctly
- Source file removal works safely for multi-file operations

---

## Advanced Features

---

### Phase 12: Performance Optimization

**Goal**: Optimize for production use

**Tasks**:
- [ ] Add parallel processing with `rayon`
- [ ] Implement streaming I/O for large files
- [ ] Add session key caching for multi-file operations
- [ ] Memory usage optimization and profiling
- [ ] Adaptive buffer sizing based on storage type

**Dependencies**: Phase 11 ✅

**Estimated Duration**: 3-4 days

**Success Criteria**:
- Significant performance improvement for large files
- Efficient memory usage across operations
- Parallel processing scales well with available cores
- Session key caching reduces redundant operations

---

### Phase 13: Add Secure Viewing (`cryptview`)

**Goal**: View encrypted files without persistent decryption

**Tasks**:
- [ ] Create `viewing/` module with streaming decryption
- [ ] Create `bin/cryptview.rs` for file viewing
- [ ] Integration with `$PAGER` and external viewers
- [ ] Secure temporary file handling with cleanup
- [ ] Memory locking to prevent swapping

**Dependencies**: Phase 12 ✅

**Estimated Duration**: 4-5 days

**Success Criteria**:
- Can view encrypted files without creating persistent decrypted copies
- Secure integration with system pagers and viewers
- Proper cleanup of temporary data
- Memory protection against swapping

---

### Phase 14: Add Secure Editing (`cryptedit`)

**Goal**: Edit encrypted text files in-place

**Tasks**:
- [ ] Create `editing/` module with atomic file updates
- [ ] Create `bin/cryptedit.rs` for text file editing
- [ ] Integration with `$EDITOR` and external editors
- [ ] Backup and rollback functionality
- [ ] Change detection and re-encryption

**Dependencies**: Phase 13 ✅

**Estimated Duration**: 4-5 days

**Success Criteria**:
- Can edit encrypted files securely in-place
- Atomic updates prevent data loss
- Backup and rollback mechanisms work reliably
- Integration with system editors is seamless

---

## Production Readiness

### Phase 15: Comprehensive Testing

**Goal**: Ensure reliability and security

**Tasks**:
- [ ] Unit tests for all crypto operations
- [ ] Integration tests for all CLI binaries
- [ ] Property-based testing for edge cases
- [ ] Security testing and memory safety validation
- [ ] Cross-platform compatibility testing

**Dependencies**: Phase 14 ✅

**Estimated Duration**: 4-5 days

**Success Criteria**:
- Comprehensive test coverage (>90%)
- All edge cases covered with property-based testing
- Security validation passes
- Cross-platform compatibility verified

---

### Phase 16: Documentation and Polish

**Goal**: Prepare for release

**Tasks**:
- [ ] Add comprehensive CLI help and man pages
- [ ] Create usage examples and tutorials
- [ ] Code review and refactoring
- [ ] Performance benchmarking
- [ ] Security audit preparation

**Dependencies**: Phase 15 ✅

**Estimated Duration**: 3-4 days

**Success Criteria**:
- Complete documentation for all features
- Performance benchmarks meet targets
- Code quality standards met
- Ready for security audit

---

### Phase 17: Release Preparation

**Goal**: Package and distribute

**Tasks**:
- [ ] Set up CI/CD pipeline
- [ ] Create release packages for multiple platforms
- [ ] Security audit and penetration testing
- [ ] Release notes and migration guides
- [ ] Binary signing and distribution

**Dependencies**: Phase 16 ✅

**Estimated Duration**: 5-7 days

**Success Criteria**:
- Automated build and release pipeline
- Security audit passed
- Multi-platform packages ready
- Release documentation complete

---

## Future Enhancements (Phase 18+)

### Post-Quantum Cryptography (Phase 18+)
- CRYSTALS-Kyber key encapsulation
- CRYSTALS-Dilithium digital signatures
- Hybrid classical/post-quantum mode

### Key Escrow and Recovery (Phase 19+)
- Shamir's Secret Sharing
- Multi-party authorization
- Audit trails and compliance

### Streaming Mode (Phase 20+)
- Chunked encryption for large files
- Merkle tree integrity verification
- Parallel processing

### Advanced Compression (Phase 21+)
- Zstandard, LZ4, Brotli integration
- Automatic compression selection
- Performance optimization

### Cloud Storage Integration (Phase 22+)
- S3-compatible storage
- Encrypted sync capabilities
- Backup automation

## Risk Assessment

### Low Risk Phases
- ✅ Phases 1-9.75: Core infrastructure and single-file operations (COMPLETE)
- Phases 10-11: Multi-file operations (building on proven foundation)
- Phases 15-17: Testing, documentation, and release (well-defined processes)

### Medium Risk Phases
- Phase 12: Performance optimization (may require refactoring)
- Phase 13: Secure viewing (moderate security complexity)

### High Risk Phases
- Phase 14: Secure editing (complex security requirements with external editors)
- Future enhancements: Post-quantum cryptography and advanced features

## Success Metrics

### Phase Completion Criteria
- All tasks completed and tested
- Code review passed
- Documentation updated
- Integration tests passing
- Performance benchmarks met

### Overall Project Success
- Core phases 1-17 completed
- Comprehensive test coverage (>90%)
- Security audit passed
- Performance targets met
- Documentation complete

### Release Milestones
- **v0.5.0**: Phase 11 complete (Full multi-file support)
- **v1.0.0**: Phase 14 complete (All core features)
- **v1.1.0**: Phase 17 complete (Production ready)

See [CHANGELOG.md](CHANGELOG.md) for version history and [ARCHITECTURE.md](ARCHITECTURE.md) for system design details.