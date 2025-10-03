# Feature Backlog

> **High-level roadmap ordered by priority. When starting work on an item, create detailed implementation plan in `CURRENT_WORK.md`**

## 🎯 CURRENT WORK
*No active work - ready for next priority item*

## 📋 PRIORITY ROADMAP

1. **Test Suite Stabilization**: Fix XChaCha20 salt length validation, filename output path edge cases, and add comprehensive XChaCha20 default algorithm selection tests
2. **Trait-Based System Architecture Review**: Address V1/V2 header version selection issues discovered during integration test analysis
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
