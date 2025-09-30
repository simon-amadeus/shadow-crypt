# Implementation Roadmap

Complete 20-phase implementation plan for the crypto file encryption system.

## Latest Development Cycle Completion (September 30, 2025)

**✅ Phase 9 Successfully Completed** - Source file removal support + Major CLI simplification

**Key Achievement**: Exceeded scope by implementing user-suggested CLI simplification alongside planned source removal functionality.

**Major Insight**: User feedback about removing output file arguments led to dramatically improved UX:
- **Old CLI**: `lock input.txt output.txt.enc` (confusing, error-prone)  
- **New CLI**: `lock input.txt` → auto-creates `input.txt.enc` (intuitive!)

**Impact**: The simplified interface makes the tools much more approachable while maintaining all security features.

**Next Focus**: Phase 9.5 (Security Audit) as prioritized by user feedback.

---

## Overview

The implementation is organized into 20 focused phases, each with specific goals and deliverables. This approach ensures:

- **Incremental Progress**: Each phase builds on previous work
- **Testable Milestones**: Clear success criteria for each phase
- **Risk Management**: Early identification and mitigation of issues
- **Maintainable Codebase**: Continuous refactoring and improvement

## Phase Status

- ✅ **Phase 1**: Module structure and architecture foundation (**COMPLETE**)
- ✅ **Phase 2**: Header implementation with serialization (**COMPLETE**)
- ✅ **Phase 3**: Core cryptographic operations (**COMPLETE**)
- ✅ **Phase 4**: Basic file encryption (**COMPLETE**)
- ✅ **Phase 5**: Basic file decryption (**COMPLETE**)
- ✅ **Phase 6**: Filename obfuscation (**COMPLETE**)
- ✅ **Phase 7**: Filename restoration (**COMPLETE**)
- ✅ **Phase 8**: File listing capability (**COMPLETE**)
- ✅ **Phase 8.5**: Critical user experience fixes (**COMPLETE**)
- ✅ **Phase 9**: Source file removal support for single-file operations (**COMPLETE** - Major CLI simplification achieved)
- 🚧 **Phase 9.5**: Security audit (**CURRENT PRIORITY** - User requested ASAP)
- ⏳ **Phase 10**: Multi-file encryption support (**REPRIORITIZED**)
- ⏳ **Phase 11**: Multi-file decryption support (**REPRIORITIZED**)

---

## Core Implementation Phases (1-11)

### Phase 1: Set Up Module Structure ✅ **COMPLETED**

**Goal**: Organize codebase according to vertical slicing architecture

**Completed Tasks**:
- ✅ Create `shared/`, `encryption/`, `decryption/`, `listing/`, `viewing/`, `editing/` module directories
- ✅ Set up basic `mod.rs` files with proper module exports
- ✅ Update `lib.rs` to expose new module structure
- ✅ Create binary entry points for all five tools
- ✅ Configure Cargo.toml with multiple binary targets
- ✅ Fix compilation errors and ensure clean build

**Deliverables**: Complete vertical slicing architecture with clean compilation

**Status**: Successfully implemented. Project ready for Phase 2.

---

### Phase 2: Complete Header Implementation ✅ **COMPLETED**

**Goal**: Finish the file header format with full serialization

**Completed Tasks**:
- ✅ Complete `Header` struct with all fields from design specification
- ✅ Implement serialization to bytes (write header to file)
- ✅ Implement deserialization from bytes (read header from file)
- ✅ Add header validation and magic number checking
- ✅ Add comprehensive unit tests for header operations
- ✅ Implement `FileMetadata` structure with complete serialization
- ✅ Add `CompressionType` enum for future algorithm support
- ✅ Enhanced bounds checking and validation in deserialization
- ✅ Add algorithm-specific parameter helper methods

**Dependencies**: Phase 1 ✅

**Actual Duration**: 1 day

**Success Criteria**: ✅ **ALL MET**
- ✅ Header serialization roundtrip tests pass (22 comprehensive tests)
- ✅ Magic number validation works correctly
- ✅ Error handling covers all edge cases
- ✅ Clean compilation with no warnings

**Deliverables**: ✅ **COMPLETED**
- Production-ready header format implementation
- Comprehensive test suite with 100% pass rate
- Complete API documentation
- Security-focused validation and bounds checking

**Status**: Successfully implemented. Ready for Phase 3.

---

### Phase 3: Implement Core Cryptographic Operations ✅ **COMPLETED**

**Goal**: Build secure crypto primitives in `shared/crypto/`

**Completed Tasks**:
- ✅ Added cryptographic dependencies to Cargo.toml (aes-gcm, argon2, getrandom, zeroize, hkdf, sha2, thiserror)
- ✅ Implemented AES-256-GCM authenticated encryption/decryption with comprehensive validation
- ✅ Implemented secure nonce generation using cryptographically secure RNG
- ✅ Implemented Argon2id key derivation with adaptive parameters (64MB memory, 5 iterations, 4 threads)
- ✅ Added HKDF key derivation for file-specific keys from master key
- ✅ Implemented secure random key and salt generation utilities
- ✅ Enhanced MasterKeyManager with key caching for performance
- ✅ Added comprehensive error handling throughout crypto operations
- ✅ Implemented 18 new unit tests for all cryptographic functions

**Dependencies**: Phase 2 ✅

**Actual Duration**: 1 day

**Success Criteria**: ✅ **ALL MET**
- ✅ Crypto operations pass comprehensive test suite (18 new tests, 40 total)
- ✅ Proper error handling for all failure modes implemented
- ✅ Memory zeroization works correctly with SecretVec
- ✅ Performance meets requirements with key caching and efficient algorithms

**Deliverables**: ✅ **COMPLETED**
- Production-ready AES-256-GCM implementation with comprehensive validation
- Complete Argon2id key derivation with adaptive parameters
- HKDF-based file key derivation system
- MasterKeyManager with intelligent caching
- Comprehensive test suite with 100% pass rate
- Complete API documentation with usage examples

**Status**: Successfully implemented. Ready for Phase 4.

---

### Phase 4: Build Basic File Encryption ✅ **COMPLETED**

**Goal**: Create core encryption functionality in `encryption/` module

**Completed Tasks**:
- ✅ Implemented single file encryption with full header integration
- ✅ Added password-based key derivation using Phase 3 crypto primitives
- ✅ Generated secure random salts and nonces per file using Phase 3 utilities
- ✅ Stored file metadata (permissions, timestamps, SHA-256 hash) in header
- ✅ Added atomic file writing with error recovery
- ✅ Integrated AES-256-GCM and Argon2id from Phase 3
- ✅ Implemented separate encryption for filename, directory path, metadata, and content
- ✅ Added comprehensive unit tests for encryption functionality
- ✅ Created working `lock` binary for command-line encryption

**Dependencies**: Phase 3 ✅

**Actual Duration**: 1 day

**Success Criteria**: ✅ **ALL MET**
- ✅ Files encrypt successfully with proper headers
- ✅ Metadata preservation works correctly
- ✅ Error recovery handles interruptions with atomic writes
- ✅ Integration tests pass with Phase 3 crypto primitives
- ✅ Command-line binary works for real-world usage

**Deliverables**: ✅ **COMPLETED**
- Complete file encryption implementation
- Working `lock` binary with CLI interface
- Comprehensive test suite with 100% pass rate
- Atomic file operations with error recovery
- Cross-platform metadata handling

**Status**: Successfully implemented. Ready for Phase 5.

---

### Phase 5: Build Basic File Decryption ✅ **COMPLETED**

**Goal**: Create core decryption functionality in `decryption/` module

**Completed Tasks**:
- ✅ Implemented single file decryption with header parsing
- ✅ Added GCM authentication tag verification before decryption
- ✅ Implemented original file metadata restoration after decryption
- ✅ Added graceful decryption error handling with user-friendly messages
- ✅ Implemented SHA-256 integrity verification of decrypted content
- ✅ Created comprehensive integration tests for roundtrip functionality
- ✅ Enhanced `unlock` binary with interactive CLI interface

**Dependencies**: Phase 4 ✅

**Actual Duration**: 1 day

**Success Criteria**: ✅ **ALL MET**
- ✅ Roundtrip encryption/decryption works perfectly
- ✅ Authentication failures are properly detected with clear error messages
- ✅ Metadata restoration preserves file permissions and attributes
- ✅ Error messages are user-friendly and informative
- ✅ Integrity verification prevents data corruption
- ✅ Working command-line binary for real-world usage

**Deliverables**: ✅ **COMPLETED**
- Complete file decryption implementation in `decryption/decrypt_file.rs`
- Working `unlock` binary with interactive password input
- Comprehensive test suite with 8 integration tests
- Roundtrip compatibility with Phase 4 encryption
- Cross-platform metadata restoration

**Status**: Successfully implemented. Ready for Phase 6.

---

### Phase 6: Add Filename Obfuscation ✅ **COMPLETED**

**Goal**: Implement secure filename obfuscation in `encryption/` module

**Completed Tasks**:
- ✅ Create HKDF-based filename obfuscation algorithm
- ✅ Add collision detection and resolution
- ✅ Store encrypted original filename in header
- ✅ Make obfuscation optional via CLI flag
- ✅ Add filename length padding for privacy

**Dependencies**: Phase 5 ✅

**Actual Duration**: 1 day (2-4 hour cycle)

**Success Criteria**: ✅ **ALL MET**
- ✅ Filename obfuscation is collision-resistant (SHA-256 + counter-based resolution)
- ✅ Original filenames are recoverable (encrypted in headers)
- ✅ Privacy protection prevents length leakage (uniform Base64url encoding)
- ✅ CLI integration works smoothly (`--obfuscate` flag with backwards compatibility)

**Deliverables**: ✅ **COMPLETED**
- Production-ready filename obfuscation with HKDF-SHA256
- Comprehensive test suite with 16 unit tests (100% pass rate)
- CLI integration with help text and status messages
- Security-focused implementation with collision resistance

**Status**: Successfully implemented. Ready for Phase 7.

---

### Phase 7: Add Filename Restoration ✅ **COMPLETED**

**Goal**: Implement filename restoration in `decryption/` module

**Completed Tasks**:
- ✅ Parse encrypted filename from header
- ✅ Decrypt and restore original filename
- ✅ Handle both obfuscated and non-obfuscated files
- ✅ Validate filename integrity with GCM authentication tags
- ✅ Add proper error handling for corruption

**Dependencies**: Phase 6 ✅

**Actual Duration**: 1 day (2-4 hour cycle)

**Success Criteria**: ✅ **ALL MET**
- ✅ Filename restoration is 100% reliable
- ✅ Both obfuscated and plain files work correctly
- ✅ Corruption detection prevents silent failures
- ✅ Unicode filenames are handled properly

**Deliverables**: ✅ **COMPLETED**
- Production-ready filename restoration with AES-256-GCM decryption
- Enhanced `unlock` binary with intelligent output path determination
- Comprehensive test suite with 6 integration tests (100% pass rate)
- Security-focused implementation with authentication verification

**Status**: Successfully implemented. Ready for Phase 8.

---

### Phase 8: Build File Listing Capability ✅ **COMPLETED**

**Goal**: Create encrypted file listing in `listing/` module

**Completed Tasks**:
- ✅ Implemented header-only reading (no full decryption required)
- ✅ Added encrypted filename parsing and original name display
- ✅ Created file metadata extraction (sizes, dates) from headers
- ✅ Implemented directory handling with mixed encrypted/regular files
- ✅ Added filtering and sorting options (by original filename)
- ✅ Created comprehensive CLI interface for `cryptls` binary
- ✅ Added graceful error handling for wrong passwords and corrupted files

**Dependencies**: Phase 7 ✅

**Actual Duration**: 1 day (4-hour cycle)

**Success Criteria**: ✅ **ALL MET**
- ✅ Listing works without requiring passwords for file detection
- ✅ Original filenames are displayed correctly with proper password
- ✅ Metadata is accurate and well-formatted in tabular output
- ✅ Performance is good for large directories with header-only reading

**Deliverables**: ✅ **COMPLETED**
- Production-ready file listing with header-only scanning
- Working `cryptls` binary with comprehensive CLI interface
- Comprehensive test suite with 9 integration tests (100% pass rate)
- Clean tabular output with size formatting and timestamp display

**Status**: Successfully implemented. Ready for Phase 9.

---

### Phase 9: Source File Removal Support ✅ **COMPLETED** + **Major CLI Simplification Achieved**

**Goal**: Add source file removal support for single-file operations (`--remove-source`/`--inplace`)

**User Insight**: Source file removal is more important than multi-file support and should be available for single-file operations. It's a generally useful feature that should be implemented first.

**Actual Achievement**: Exceeded scope by implementing major CLI simplification based on user feedback

**Completed Tasks**:
- ✅ Add `--remove-source` flag to `lock` binary for single-file encryption
- ✅ Add `--remove-source` flag to `unlock` binary for single-file decryption  
- ✅ Add `--inplace` alias flag for convenience
- ✅ Implement secure file deletion (overwrite before removal on supported filesystems)
- ✅ Add safety confirmation prompts for destructive operations
- ✅ Implement atomic operation: ensure encryption/decryption succeeds before source removal
- ✅ Add comprehensive error handling for removal failures
- ✅ Update help text and documentation for new flags
- ✅ Add comprehensive tests for source removal functionality
- ✅ **BONUS**: Major CLI simplification - removed confusing output file arguments
- ✅ **BONUS**: Automatic output path generation with smart defaults

**Dependencies**: Phase 8.5 ✅

**Actual Duration**: 1 day (faster than estimated due to focused implementation)

**Success Criteria**: ✅ **ALL MET**
- ✅ `lock --remove-source file.txt` encrypts and safely removes source
- ✅ `unlock --remove-source file.txt.enc` decrypts and safely removes encrypted file
- ✅ Atomic operations: removal only happens after successful encryption/decryption
- ✅ Clear safety prompts and error messages
- ✅ Comprehensive test coverage for all edge cases
- ✅ **BONUS**: Simplified CLI that "just works" without complex arguments

**Security Considerations**: ✅ **ALL ADDRESSED**
- ✅ Ensure file is fully written and verified before source removal
- ✅ Use secure deletion with random data overwriting before unlink
- ✅ Provide clear feedback about irreversible operations
- ✅ Handle partial failures gracefully (e.g., successful encryption but failed removal)

**Major Architectural Improvement**:
User feedback led to removing output file arguments entirely, resulting in much more intuitive CLI:
- **Before**: `lock input.txt output.txt.enc` (confusing, error-prone)
- **After**: `lock input.txt` → automatically creates `input.txt.enc` (intuitive!)

**Key Learnings**:
1. **User feedback quality**: Real user insight about output arguments being unnecessary was invaluable
2. **CLI design philosophy**: "Smart defaults" are better than "flexible configuration" for crypto tools
3. **Scope flexibility**: Being open to improvements beyond original scope led to better outcomes
4. **Security integration**: Secure deletion integrates well with existing cryptographic foundation

---

### Phase 9.5: Security Audit (**NEW PRIORITY PHASE** - **User Feedback**)

**Goal**: Conduct comprehensive security audit as requested by users

**Critical Security Tasks**:
- [ ] Third-party cryptographic review of AES-256-GCM implementation
- [ ] Argon2id parameter validation and side-channel analysis
- [ ] Memory safety audit (SecureVec, zeroization, mlock usage)
- [ ] Timing attack resistance verification
- [ ] File format security analysis
- [ ] CLI input sanitization and injection testing
- [ ] Dependency security audit (crypto crates, supply chain)
- [ ] Penetration testing of complete workflow

**Deliverables**:
- [ ] Professional security audit report
- [ ] Remediation plan for any identified issues
- [ ] Security certification documentation
- [ ] Updated security documentation with audit results

**Dependencies**: Phase 10 ✅

**Estimated Duration**: 7-14 days (external audit + remediation)

**Success Criteria**:
- Professional security audit passes with no critical issues
- All medium/high findings addressed
- Security documentation updated with audit results
- Users receive audit report and remediation evidence

**Note**: This phase was added in response to urgent user request for security validation.

---

### Phase 10: Multi-File Encryption Support (**REPRIORITIZED** after source removal)

**Goal**: Support encrypting multiple individual files (not directories)

**Revised Approach Based on User Feedback**:
- **Focus**: Multi-file support building on single-file source removal from Phase 9
- **Postponed**: Directory encryption functionality
- **Inherit**: Source removal support from Phase 9

**Tasks**:
- [ ] Add support for multiple file arguments to `lock` binary
- [ ] Implement batch processing for multiple individual files
- [ ] Add progress indicators for multi-file operations
- [ ] Support glob patterns for file selection
- [ ] Enhance error handling for partial failures
- [ ] Add parallel processing for performance
- [ ] Extend `--remove-source` support to multi-file operations

**Dependencies**: Phase 9 ✅ (Source file removal)

**Estimated Duration**: 2-3 days

**Success Criteria**:
- Can encrypt multiple individual files in one command
- Progress feedback shows per-file and overall progress
- Robust error handling for individual file failures
- Source removal works safely for multi-file operations
- Performance scales well with file count

---

### Phase 11: Multi-File Decryption Support (**REPRIORITIZED**)

**Goal**: Support decrypting multiple individual files

**Tasks**:
- [ ] Add support for multiple file arguments to `unlock` binary
- [ ] Implement batch processing for multiple encrypted files
- [ ] Add automatic output path determination for batch operations
- [ ] Support wildcard/glob patterns for encrypted file selection
- [ ] Add progress indicators and error handling
- [ ] Extend `--remove-source` support to multi-file decryption

**Dependencies**: Phase 10 ✅

**Estimated Duration**: 2-3 days

**Success Criteria**:
- Can decrypt multiple files in one command
- Automatic filename restoration works for all files
- Progress feedback and error handling work correctly
- Source file removal works safely for multi-file operations

---

## Advanced Features (12-17)

---

### Phase 11: File Editing Support (`cryptedit`)

**Goal**: Implement secure in-place editing of encrypted files

**Tasks**:
- [ ] Update `lock` to accept multiple file/directory arguments
- [ ] Update `unlock` to handle multiple paths
- [ ] Add progress reporting for batch operations
- [ ] Implement session key caching for performance
- [ ] Add resume capability for interrupted operations

**Dependencies**: Phase 13 ✅

**Estimated Duration**: 2-3 days

---

### Phase 12: Add Secure Viewing (`cryptview`)

**Goal**: View encrypted files without persistent decryption

**Tasks**:
- [ ] Create `viewing/` module with streaming decryption
- [ ] Create `bin/cryptview.rs` for file viewing
- [ ] Integration with `$PAGER` and external viewers
- [ ] Secure temporary file handling with cleanup
- [ ] Memory locking to prevent swapping

**Dependencies**: Phase 14 ✅

**Estimated Duration**: 4-5 days

---

### Phase 13: Add Secure Editing (`cryptedit`)

**Goal**: Edit encrypted text files in-place

**Tasks**:
- [ ] Create `editing/` module with atomic file updates
- [ ] Create `bin/cryptedit.rs` for text file editing
- [ ] Integration with `$EDITOR` and external editors
- [ ] Backup and rollback functionality
- [ ] Change detection and re-encryption

**Dependencies**: Phase 15 ✅

**Estimated Duration**: 4-5 days

---

## Production Readiness (17-20)

### Phase 14: Performance Optimization

**Goal**: Optimize for production use

**Tasks**:
- [ ] Add parallel processing with `rayon`
- [ ] Implement streaming I/O for large files
- [ ] Add session key caching
- [ ] Memory usage optimization and profiling
- [ ] Adaptive buffer sizing based on storage type

**Dependencies**: Phase 16 ✅

**Estimated Duration**: 5-7 days

---

### Phase 15: Comprehensive Testing

**Goal**: Ensure reliability and security

**Tasks**:
- [ ] Unit tests for all crypto operations
- [ ] Integration tests for all CLI binaries
- [ ] Property-based testing for edge cases
- [ ] Security testing and memory safety validation
- [ ] Cross-platform compatibility testing

**Dependencies**: Phase 17 ✅

**Estimated Duration**: 7-10 days

---

### Phase 16: Documentation and Polish

**Goal**: Prepare for release

**Tasks**:
- [ ] Add comprehensive CLI help and man pages
- [ ] Create usage examples and tutorials
- [ ] Code review and refactoring
- [ ] Performance benchmarking
- [ ] Security audit preparation

**Dependencies**: Phase 18 ✅

**Estimated Duration**: 5-7 days

---

### Phase 17: Release Preparation

**Goal**: Package and distribute

**Tasks**:
- [ ] Set up CI/CD pipeline
- [ ] Create release packages for multiple platforms
- [ ] Security audit and penetration testing
- [ ] Release notes and migration guides
- [ ] Binary signing and distribution

**Dependencies**: Phase 19 ✅

**Estimated Duration**: 7-10 days

---

## Future Enhancements (18+)

### Post-Quantum Cryptography (Phase 21+)
- CRYSTALS-Kyber key encapsulation
- CRYSTALS-Dilithium digital signatures
- Hybrid classical/post-quantum mode

### Key Escrow and Recovery (Phase 22+)
- Shamir's Secret Sharing
- Multi-party authorization
- Audit trails and compliance

### Streaming Mode (Phase 23+)
- Chunked encryption for large files
- Merkle tree integrity verification
- Parallel processing

### Advanced Compression (Phase 24+)
- Zstandard, LZ4, Brotli integration
- Automatic compression selection
- Performance optimization

### Cloud Storage Integration (Phase 25+)
- S3-compatible storage
- Encrypted sync capabilities
- Backup automation

## Risk Assessment

### Low Risk Phases
- Phases 1-3: Core infrastructure (✅ Phase 1 complete)
- Phases 9-11: CLI binaries
- Phase 18-19: Testing and documentation

### Medium Risk Phases
- Phases 4-8: Core crypto functionality
- Phases 12-14: Directory and multi-file support

### High Risk Phases
- Phases 15-16: Secure viewing/editing (complex security requirements)
- Phase 17: Performance optimization (may require significant refactoring)
- Phase 20: Release preparation (external dependencies)

## Success Metrics

### Phase Completion Criteria
- All tasks completed and tested
- Code review passed
- Documentation updated
- Integration tests passing
- Performance benchmarks met

### Overall Project Success
- All 20 phases completed
- Comprehensive test coverage (>90%)
- Security audit passed
- Performance targets met
- Documentation complete

See [CHANGELOG.md](CHANGELOG.md) for version history and [ARCHITECTURE.md](ARCHITECTURE.md) for system design details.