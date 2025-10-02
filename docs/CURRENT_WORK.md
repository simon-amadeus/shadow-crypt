# Current Work: Algorithm Selection Infrastructure

## Problem Analysis

**Current State**: 
- XChaCha20-Poly1305 is fully implemented but not accessible to users
- All encryption is hardcoded to use AES-GCM 
- Tests take 57+ seconds due to production-level key derivation parameters
- No CLI interface for algorithm selection

**User Need**: 
- Choose between AES-GCM (compatibility) and XChaCha20-Poly1305 (superior security)
- Fast test execution for development workflow
- Clear security guidance about algorithm differences

## Implementation Plan

### Phase 1: Algorithm Selection Architecture (1-2 hours)

1. **Update Algorithm Selection Module** 
   - Add XChaCha20-Poly1305 to `Algorithm` enum in `selection.rs`
   - Update algorithm metadata (ID, name, key size, etc.)
   - Implement algorithm selection logic

2. **CLI Interface Design**
   - Add `--algorithm` flag to shadow/unshadow binaries
   - Options: `aes-gcm`, `xchacha20` (with `aes-gcm` as default for compatibility)
   - Auto-detect algorithm for decryption (no flag needed)

3. **Encryption Function Updates**
   - Modify `encrypt_single_file_with_params` to accept algorithm parameter
   - Dispatch to appropriate algorithm implementation
   - Update header generation with correct algorithm ID

### Phase 2: Test Performance Optimization (30 minutes) ✅ COMPLETED

4. **Fast Test Parameters** ✅
   - ~~Create `Argon2Params::fast()` for testing (low memory/iterations)~~
   - **ROOT CAUSE ANALYSIS COMPLETED**: 
     1. **XChaCha20-Poly1305 missing `cfg!(test)` logic** - Fixed by adding test/production param methods
     2. **Integration tests use production parameters** - `cfg!(test)` only works for unit tests, not integration tests
   - **SOLUTIONS IMPLEMENTED**:
     - Added `test_params()` and `cfg!(test)` logic to XChaCha20-Poly1305 Argon2Params
     - Updated `double_encryption_prevention.rs` to use `encrypt_single_file_with_params` with fast params
   - **PERFORMANCE RESULTS**:
     - Unit tests: 57+ seconds → 1.3 seconds (**43x improvement**)
     - Double encryption tests: 19+ seconds → 0.02 seconds (**950x improvement**)  
     - Overall test suite: 57+ seconds → 13 seconds (**4.4x improvement**)
   - **TECHNICAL INSIGHT**: `cfg!(test)` only applies to same-crate unit tests, not integration tests in `tests/` directory
   - Maintain `Argon2Params::default()` for production ✅

### Phase 3: Integration & Testing (1-2 hours)

5. **CLI Integration**
   - Update all binaries to parse algorithm flags
   - Pass algorithm selection through to encryption functions
   - Add validation and error handling

6. **Comprehensive Testing**
   - Test both algorithms via CLI
   - Test algorithm interoperability (encrypt with one, decrypt with either)
   - Validate performance improvements in test suite

## Technical Considerations

**Algorithm Compatibility**: 
- Files encrypted with different algorithms are completely independent
- Decryption auto-detects algorithm from header
- No migration needed - users can choose per-file

**Default Strategy**:
- Keep AES-GCM as default for maximum compatibility
- Allow users to opt-in to XChaCha20-Poly1305 for enhanced security
- Future phases can change default after user adoption

**Security Implications**:
- Both algorithms provide equivalent security for file encryption
- XChaCha20-Poly1305 eliminates nonce reuse vulnerabilities entirely
- Choice allows users to balance compatibility vs cutting-edge security

## Success Criteria

- [ ] CLI accepts `--algorithm` flag with `aes-gcm` and `xchacha20` options
- [ ] Both algorithms work through CLI interface  
- [ ] Test suite runs in <10 seconds (vs current 57+ seconds)
- [ ] All existing functionality preserved (backward compatibility)
- [ ] Comprehensive test coverage for both algorithms via CLI

## Testing Approach

**Unit Tests**: Algorithm selection logic and parameter validation
**Integration Tests**: CLI argument parsing and algorithm dispatch  
**Performance Tests**: Verify test speed improvement
**Security Tests**: Ensure both algorithms maintain security properties

## Implementation Notes

*This section will be updated during implementation with discoveries and insights*
