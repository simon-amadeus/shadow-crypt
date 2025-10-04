# Current Development Cycle: Shadows Binary Implementation

**Cycle Start**: 2025-10-04  
**Priority Item**: shadows Binary - Properly implement directory listing according to docs/specs/FEATURE_REQUIREMENTS.md

## 📋 OBJECTIVE

Implement a fully functional `shadows` binary that scans directories for encrypted `.shadow` files and displays their metadata with original filename decryption.

## 🎯 SUCCESS CRITERIA

- ✅ Directory scanning finds all `.shadow` files recursively
- ✅ TLV header parsing extracts file metadata (algorithm, version, original filename)
- ✅ Password verification attempts to decrypt original filenames
- ✅ Professional table output with color coding and proper formatting
- ✅ Performance reporting for scan operations
- ✅ Error handling for inaccessible files/directories
- ✅ Smart ordering: successful decryptions first, then failed attempts

## 🧩 CURRENT STATE ANALYSIS

**Existing Implementation Review:**
- ✅ `ListingService` in domain layer - Has core directory scanning logic
- ✅ `ListingWorkflow` in application layer - Has basic workflow structure but incomplete
- ✅ `shadows.rs` binary - Has CLI parsing and output formatting
- ✅ TLV header parsing infrastructure exists
- ❌ ListingWorkflow has TODO placeholders instead of real implementation
- ❌ No integration between domain service and application workflow

**Key Missing Pieces:**
1. Complete ListingWorkflow implementation using existing ListingService
2. Proper password verification logic in ListingService
3. File discovery mechanism (currently only processes given files)
4. Integration between existing domain and application layers

## 🗺️ IMPLEMENTATION APPROACH

### Phase 1: Wire Domain Service to Application Layer ✅ COMPLETE
- ✅ Updated ListingWorkflow to use the existing ListingService
- ✅ Removed TODO placeholders and implemented real directory scanning
- ✅ Ensured proper error propagation from domain to application layer
- ✅ Fixed type conversions between domain and application layer types

### Phase 2: Complete Domain Service Implementation  ✅ COMPLETE
- ✅ Fixed password verification in ListingService.try_parse_header()
- ✅ Implemented actual password validation through cryptographic decryption
- ✅ Added proper error handling for corrupted/inaccessible files
- ✅ Password verification now correctly shows success/failure states

### Phase 3: Enhance CLI Output
- ❓ Improve table formatting based on feature requirements
- ❓ Add color coding for success/failure indicators  
- ❓ Implement smart ordering (successful decryptions first)
- ❓ Add human-readable file sizes

### Phase 4: Integration Testing
- ❓ Test with various directory structures
- ❓ Validate password verification works correctly  
- ❓ Ensure graceful handling of edge cases

## 🔍 TECHNICAL CONSIDERATIONS

**Password Verification Strategy:**
- Currently ListingService assumes password is valid if header parses
- Need to implement actual password verification (decrypt a small portion or validate checksum)
- Should gracefully handle wrong passwords without failing entire scan

**File Discovery:**
- Feature requirements don't specify recursive scanning, but implementation should handle subdirectories
- Need to identify encrypted files by TLV header magic bytes, not just `.shadow` extension
- Handle obfuscated filenames correctly

**Performance:**
- Large directory scanning should be efficient
- Progress indicators for directories with many files
- Consider memory usage for very large directories

## 📁 FILES TO MODIFY

1. **src/application/workflows/listing_workflow.rs** - Complete implementation using domain service
2. **src/domain/services/listing_service.rs** - Fix password verification and improve error handling  
3. **src/bin/shadows.rs** - Enhance output formatting and user experience
4. **src/cli/shadows.rs** - May need CLI improvements (if exists)

## 🧪 VALIDATION PLAN

1. **Unit Tests**: Verify ListingService correctly parses various file types
2. **Integration Tests**: Test complete workflow with real encrypted files
3. **CLI Tests**: Verify output formatting and error handling
4. **Edge Case Tests**: Empty directories, corrupted files, wrong passwords

## 📝 NOTES

- Existing domain architecture is solid - just need to complete the integration
- ListingService already has the right structure, needs refinement
- Focus on leveraging existing infrastructure rather than rewriting
- TLV header parsing is already functional based on existing code