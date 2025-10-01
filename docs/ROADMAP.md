# Implementation Roadmap

## 🎯 NEXT PRIORITIES (Work in Progress)

- ⚡ **Phase 9.94.4**: Version-Specific Module Creation (**NEXT PRIORITY** - Encapsulate V1 logic in `versions/v1/`)
- ⚡ **Phase 10**: Multi-file encryption support (**HIGH PRIORITY** - CORE user functionality)

## 📋 FUTURE PHASES (Planned Work)

- 📋 **Phase 9.94.5**: Algorithm-specific module organization  
- 📋 **Phase 9.94.6**: Integration testing and cleanup
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

## Phase 9.94.4: Version-Specific Module Creation (NEXT PRIORITY)

**Goal**: Encapsulate Version 1 specific code in `src/shared/versions/v1/` to enable clean V2 addition

**Rationale**: With core utilities cleanly separated, now move V1-specific code (header_core.rs, filename_auth.rs) into version-specific modules. This enables adding V2 later without touching V1 code.

**Current Focus - Implementation Tasks**:
- [ ] **Create `src/shared/versions/v1/` directory structure**
- [ ] **Move V1-specific modules**:
  - [ ] `header_core.rs` → `versions/v1/header.rs` (V1 header format and serialization)  
  - [ ] `filename_auth.rs` → `versions/v1/filename_auth.rs` (V1 authentication logic)
  - [ ] Extract V1 parts from `versioning.rs` → `versions/v1/format.rs`
- [ ] **Create version interface modules**:
  - [ ] `versions/v1/crypto_integration.rs` (V1 crypto workflow integration)
  - [ ] `versions/v1/mod.rs` (V1 public interface implementing VersionHandler trait)
  - [ ] `versions/detection.rs` (version detection from file headers)  
  - [ ] `versions/dispatch.rs` (runtime version dispatch)
  - [ ] `versions/mod.rs` (version management interface)
- [ ] **Update imports throughout codebase** to use `versions::v1::` paths
- [ ] **Maintain backward compatibility** through re-exports in main modules
- [ ] **Validate all functionality preserved** - all 130 tests must pass

**Dependencies**: Phase 9.94.3 ✅ (core utilities extraction complete)

**Success Criteria**:
- **V1 Logic Encapsulated**: All version 1 specific code contained in `versions/v1/` module
- **Clean Interfaces**: `VersionHandler` trait enables uniform version operations
- **No Functionality Loss**: All existing tests continue to pass
- **Easy V2 Addition**: Adding `versions/v2/` should require no changes to V1 or core code
- **Maintained Compatibility**: Public APIs unchanged for end users

---

## Phase 9.94.5: Algorithm-Specific Module Organization

**Goal**: Separate AES-GCM algorithm into dedicated module to enable adding ChaCha20-Poly1305

**Tasks** (After 9.94.4 completes):
- [ ] Create `src/shared/algorithms/aes_gcm/` directory
- [ ] Move AES-specific code from `crypto/`:
  - [ ] `crypto/aes.rs` → `algorithms/aes_gcm/encryption.rs` + `decryption.rs`
  - [ ] `crypto/argon2.rs` → `algorithms/aes_gcm/key_derivation.rs`
- [ ] Create algorithm interface:
  - [ ] `algorithms/aes_gcm/mod.rs` implementing `Algorithm` trait
  - [ ] `algorithms/selection.rs` for algorithm choice logic
  - [ ] `algorithms/registry.rs` for capability registration
- [ ] Update crypto operations to use algorithm modules
- [ ] Validate all crypto functionality preserved

**Dependencies**: Phase 9.94.4 ✅

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