# Feature Backlog

> **High-level roadmap ordered by priority. When starting work on an item, create detailed implementation plan in `CURRENT_WORK.md`**

## 🎯 CURRENT WORK
*No active work - ready for next priority item*

## 📋 PRIORITY ROADMAP

1. **File Scanner Module Cleanup**: Fix compilation issues in `src/listing/file_scanner.rs` from trait migration merge conflicts
2. **Multi-File Configuration Integration**: Add configuration provider support to multi-file encryption/decryption operations
3. **Module Structure Refactoring**: Improve module organization for better clarity and maintainability
4. **Versioning & Algorithm Review**: Evaluate current versioning scheme and algorithm usage for future extensibility
5. **Code Quality Polish**: Apply clippy fixes, formatting, and documentation improvements  
6. **Production Readiness**: Comprehensive testing, documentation, and release preparation

## 🔧 FUTURE CONSIDERATIONS

- **Secure Viewing (`shadowview`)**: View encrypted files without persistent decryption
- **Secure Editing (`shadowedit`)**: Edit encrypted text files in-place  
- **Post-Quantum Cryptography**: Future-proof encryption algorithms leveraging V2 header extensibility
- **Cloud Storage Integration**: Seamless encrypted backup and sync
- **Streaming I/O Optimization**: Large file handling with chunked processing *(when needed)*

---
