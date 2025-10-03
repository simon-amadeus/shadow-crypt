# Feature Backlog

> **High-level roadmap ordered by priority. When starting work on an item, create detailed implementation plan in `CURRENT_WORK.md`**

## 🎯 CURRENT WORK
*V1/V2 Complete Removal - See `docs/CURRENT_CYCLE.md` for details*

## 📋 PRIORITY ROADMAP

1. **Shadows Output Enhancement**: Fix shadows command to display original filename and more metadata (algorithm, version)
3. **Code Quality Polish**: Apply clippy fixes, formatting, and documentation improvements  
4. **Production Readiness**: Comprehensive testing, documentation, and release preparation

## 🔧 FUTURE CONSIDERATIONS

- **Integration Test Modernization**: Update tests to use trait-based system (BLOCKED: requires trait system architecture fixes first)
- **Secure Viewing (`shadowview`)**: View encrypted files without persistent decryption
- **Secure Editing (`shadowedit`)**: Edit encrypted text files in-place  
- **Post-Quantum Cryptography**: Future-proof encryption algorithms leveraging V2 header extensibility
- **Cloud Storage Integration**: Seamless encrypted backup and sync
- **Streaming I/O Optimization**: Large file handling with chunked processing *(when needed)*

---
