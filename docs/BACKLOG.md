# Feature Backlog

> **High-level roadmap ordered by priority. When starting work on an item, create detailed implementation plan in `CURRENT_WORK.md`**

## 🎯 IMPLEMENTATION GUIDANCE

**Implementation Strategy**:
- **Primary Guide**: Follow the specs in `docs/specs/DOMAIN_ARCHITECTURE.md`, `docs/specs/ARCHITECTURE_REQUIREMENTS.md` and the other spec files precisely. If conflicts arise, make plans to adapt towards the best possible outcome while taking all context into account.
- **Legacy Reference**: Proven implementations available in `legacy/src/` - extract patterns but rewrite cleanly
- **Key Legacy Assets**: 
  - TLV header system: `legacy/src/shared/header.rs` and `legacy/src/shared/versions/v3_tlv_poc.rs`
  - Configuration providers: `legacy/src/shared/algorithms/config.rs`
  - Cryptographic implementations: `legacy/src/shared/algorithms/xchacha20_poly1305/` and `legacy/src/shared/algorithms/aes_gcm/`
  - Error handling: `legacy/src/shared/core/errors.rs`
- **Clean Slate Approach**: Start from specs, reference legacy only when needed for proven patterns

## 🎯 CURRENT WORK
- no active work - ready for next cycle

## 📋 PRIORITY ROADMAP

### **P1 - Critical Missing Features (User Safety)**
*No items - critical safety issues resolved*

### **P2 - Domain Architecture (Business Logic)**
*No items - application workflows in active development*

### **P3 - CLI Integration (User Interface)**
5. **shadow Binary**: File encryption with all features (obfuscation, progress, batch processing)
6. **unshadow Binary**: File decryption with automatic filename restoration
7. **shadows Binary**: Directory listing with original filename display and metadata
8. **shadowmigrate Binary**: Version migration and format updates

## 🔧 FUTURE CONSIDERATIONS

- **CLI Duplicate Handling**: User experience design for duplicate detection prompts with options: abort, overwrite, rename, or force duplicate encryption
- **Async File Operations**: Large directory scanning optimization for 1000+ files with async I/O operations
- **Domain Event System**: Content fingerprinting operations emit domain events for audit trails and monitoring
- **Memory Management Optimization**: LRU cache for ContentHashDatabase to prevent unbounded memory growth in high-volume scenarios
- **Secure Viewing (`shadowview`)**: View encrypted files without persistent decryption
- **Secure Editing (`shadowedit`)**: Edit encrypted text files in-place  
- **Post-Quantum Cryptography**: Future-proof encryption algorithms leveraging TLV header extensibility
- **Cloud Storage Integration**: Seamless encrypted backup and sync
- **Streaming I/O Optimization**: Large file handling with chunked processing *(when needed)*

---
