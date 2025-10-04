# Customer Feedback

Add your feedback here. Keep it simple - just write what you think.

---

## New Feedback

**2025-10-04**: Content Fingerprinting Implementation - Discovered integration opportunities and architectural enhancements during content fingerprinting implementation:

**Immediate Next Cycle Enablers:**
1. **EncryptedFile I/O Implementation**: Need complete EncryptedFile parsing and serialization to finish Phase 4 directory scanning for duplicate detection. Current TLV header integration is ready, but file I/O operations are needed to scan existing .shadow files and extract ContentHash fields from headers.

2. **EncryptionService Integration**: Content fingerprinting infrastructure is ready for immediate integration with EncryptionService. DuplicateDetectorBuilder pattern enables clean dependency injection. Implementation should:
   - Calculate content hash before encryption
   - Check for duplicates using DuplicateDetector
   - Store ContentHash in TLV header during encryption
   - Prompt user when duplicates found

**Future Architecture Enhancements:**
3. **CLI Duplicate Handling**: Need user experience design for duplicate detection prompts. When duplicates found, should offer options: abort, overwrite, rename, or force duplicate encryption.

4. **Async File Operations**: Large directory scanning (1000+ files) could benefit from async I/O operations. Current implementation is synchronous and may block on large directories.

5. **Domain Event System**: Content fingerprinting operations could emit domain events for audit trails, monitoring, and future analytics features.

**Technical Quality Improvements:**
6. **Memory Management Optimization**: For high-volume scenarios (10,000+ tracked files), consider LRU cache for ContentHashDatabase to prevent unbounded memory growth.

**Root Cause Analysis:** Content fingerprinting revealed that the domain architecture is well-positioned for feature expansion. The clean separation between content hashing, duplicate detection, and file I/O enables modular development. Builder pattern proves effective for complex domain service configuration.

**Implementation Priority:** Items 1-2 are ready for immediate implementation and directly support P1 roadmap priorities. Items 3-6 are architectural improvements for future consideration.

---

## Processed Feedback

- **2025-10-04**: Complete Crypto Infrastructure Implementation - Interface mismatches after architecture migration need resolution for functional crypto operations. → **COMPLETED in v0.7.2**
- **2025-10-04**: Critical Architecture Violations in Algorithm Abstraction - Cryptographic abstractions incorrectly placed in infrastructure layer, violating clean architecture. Domain services importing from infrastructure breaks dependency inversion. Requires comprehensive refactoring to move all crypto abstractions to domain layer. → **Processed into backlog P0 item**
- **2025-10-04**: Rewrite approach guidance - Move existing code to legacy/ folder, start from scratch based on docs/specs, remove old integration tests, focus on clean new codebase aligned to target architecture. → **Processed into backlog P0 item**