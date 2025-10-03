# Feature Backlog

> **High-level roadmap ordered by priority. When starting work on an item, create detailed implementation plan in `CURRENT_WORK.md`**

## 🎯 CURRENT WORK
*No active work - ready for next priority item*

## 📋 PRIORITY ROADMAP

1. **Versioning & Algorithm Review and V3 Design**: Evaluate current versioning scheme and algorithm usage for future extensibility. Then design V3 header structure. No migration or backwards compatibility needed. this project is unreleased so breaking changes are acceptable.
2. **Deprecate v1 Header**: Deprecate and remove v1 and v2 header support. no backwards compatibility needed. clean up codebase.
3. **Shadows Output Enhancement**: Fix shadows command to display original filename and more metadata (algorithm, version)
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
