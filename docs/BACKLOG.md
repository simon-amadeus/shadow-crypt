# Feature Backlog

> **High-level roadmap ordered by priority. When starting work on an item, create detailed implementation plan in `CURRENT_WORK.md`**

## 🎯 CURRENT WORK
- **shadows Binary Implementation**: Active development in docs/CURRENT_CYCLE.md

## 📋 PRIORITY ROADMAP
- **shadowmigrate Binary**: Properly implement version migration and format updates according to docs/specs/FEATURE_REQUIREMENTS.md. please look at the current domain layer and scan it for usable implementation pieces. it should contain most of the logic already.

## 🔧 FUTURE CONSIDERATIONS

- **Async File Operations**: Large directory scanning optimization for 1000+ files with async I/O operations
- **Domain Event System**: Content fingerprinting operations emit domain events for audit trails and monitoring
- **Memory Management Optimization**: LRU cache for ContentHashDatabase to prevent unbounded memory growth in high-volume scenarios
- **Secure Viewing (`shadowview`)**: View encrypted files without persistent decryption
- **Secure Editing (`shadowedit`)**: Edit encrypted text files in-place  
- **Post-Quantum Cryptography**: Future-proof encryption algorithms leveraging TLV header extensibility
- **Cloud Storage Integration**: Seamless encrypted backup and sync
- **Streaming I/O Optimization**: Large file handling with chunked processing *(when needed)*

---
