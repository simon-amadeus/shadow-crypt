# Feature Backlog

> **H2. **4. **Secure Memory Management**: KeyMaterial with SecureBox automatic zeroization for cryptographic hygiene
5. **Algorithm Abstraction Layer**: XChaCha20-Poly1305 (default) + AES-256-GCM implementations with pluggable interface
6. **File Detection Logic**: Robust double-encryption prevention using magic number validation
7. **Content Fingerprinting**: SHA-256 infrastructure for duplicate detection using TLV ContentHash fieldte Version Compatibility Matrix**: Future-proof migration system with V1 as baseline and explicit compatibility checking
3. **Establish Error Handling Framework**: User-friendly, security-conscious error messages with actionable guidanceh-level roadmap ordered by priority. When starting work on an item, create detailed implementation plan in `CURRENT_WORK.md`**

## 🎯 IMPLEMENTATION GUIDANCE

**Architecture Foundation (v0.2.0)**: Complete clean architecture rewrite completed - all code now in domain/application/infrastructure/cli layers with placeholder implementations.

**Implementation Strategy**:
- **Primary Guide**: Follow the `docs/specs/**.md` files precisely. If conflicts arise, make plans to adapt towards the best possible outcome while taking all context into account.
- **Legacy Reference**: Proven implementations available in `legacy/src/` - extract patterns but rewrite cleanly
- **Key Legacy Assets**: 
  - TLV header system: `legacy/src/shared/header.rs` and `legacy/src/shared/versions/v3_tlv_poc.rs`
  - Configuration providers: `legacy/src/shared/algorithms/config.rs`
  - Cryptographic implementations: `legacy/src/shared/algorithms/xchacha20_poly1305/` and `legacy/src/shared/algorithms/aes_gcm/`
  - Error handling: `legacy/src/shared/core/errors.rs`
- **Clean Slate Approach**: Start from specs, reference legacy only when needed for proven patterns

## 🎯 CURRENT WORK
*No active work - ready for next cycle*

## 📋 PRIORITY ROADMAP

### **P0 - Cryptographic Foundation (Security)**
6. **Algorithm Abstraction Layer**: XChaCha20-Poly1305 (default) + AES-256-GCM implementations with pluggable interface
7. **File Detection Logic**: Robust double-encryption prevention using magic number validation
8. **Content Fingerprinting**: SHA-256 infrastructure for duplicate detection using TLV ContentHash field

### **P1 - Critical Missing Features (User Safety)**
8. **Double Password Verification**: Confirmation prompt during encryption to prevent data loss from password typos
9. **Duplicate Content Detection**: Implement ContentHash TLV field usage to prevent redundant encryption
10. **Fix --keep Flag Behavior**: Correct CLI flag implementation (current behavior is opposite of spec)
11. **Fix Source Removal Default**: Remove source files by default with --keep flag to preserve

### **P2 - Domain Architecture (Business Logic)**
12. **Domain Entities Implementation**: EncryptedFile, PlaintextFile, CryptoSession, DuplicateDetector, FileMetadata
13. **Domain Services Implementation**: EncryptionService, DecryptionService, ListingService, MigrationService
14. **Repository Interfaces**: FileRepository + PasswordRepository (stateless design - no ConfigRepository)
15. **Application Workflows**: EncryptionWorkflow, DecryptionWorkflow, ListingWorkflow, MigrationWorkflow

### **P3 - CLI Integration (User Interface)**
16. **shadow Binary**: File encryption with all features (obfuscation, progress, batch processing)
17. **unshadow Binary**: File decryption with automatic filename restoration
18. **shadows Binary**: Directory listing with original filename display and metadata
20. **shadowmigrate Binary**: Version migration and format updates


## 🔧 FUTURE CONSIDERATIONS

- **Secure Viewing (`shadowview`)**: View encrypted files without persistent decryption
- **Secure Editing (`shadowedit`)**: Edit encrypted text files in-place  
- **Post-Quantum Cryptography**: Future-proof encryption algorithms leveraging TLV header extensibility
- **Cloud Storage Integration**: Seamless encrypted backup and sync
- **Streaming I/O Optimization**: Large file handling with chunked processing *(when needed)*

---
