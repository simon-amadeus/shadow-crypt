# Feature Backlog

> **High-level roadmap ordered by priority. When starting work on an item, create detailed implementation plan in `CURRENT_WORK.md`**

## 🎯 CURRENT WORK
*No active work - ready for next priority item*

## 📋 PRIORITY ROADMAP

1. **XChaCha20 Salt Length Investigation**: Resolve "Invalid salt length" error in XChaCha20 trait-based encryption (discovered during architecture review)
2. **Library Test Suite Stabilization**: Fix remaining 2 failed library tests (salt length related, affects development confidence)
3. **Versioning & Algorithm Review**: Evaluate current versioning scheme and algorithm usage for future extensibility
4. **Code Quality Polish**: Apply clippy fixes, formatting, and documentation improvements  
5. **Production Readiness**: Comprehensive testing, documentation, and release preparation

## 🔧 FUTURE CONSIDERATIONS

- **Integration Test Modernization**: Update tests to use trait-based system (BLOCKED: requires trait system architecture fixes first)
- **Secure Viewing (`shadowview`)**: View encrypted files without persistent decryption
- **Secure Editing (`shadowedit`)**: Edit encrypted text files in-place  
- **Post-Quantum Cryptography**: Future-proof encryption algorithms leveraging V2 header extensibility
- **Cloud Storage Integration**: Seamless encrypted backup and sync
- **Streaming I/O Optimization**: Large file handling with chunked processing *(when needed)*

---
