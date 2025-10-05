# Feature Backlog

> **High-level roadmap ordered by priority. When starting work on an item, create detailed implementation plan in `CURRENT_WORK.md`**

## 🎯 CURRENT WORK
- **Architecture Specification Design**: Creating comprehensive 3-layered architecture specs with vertical slicing (see docs/CURRENT_CYCLE.md)

## 📋 PRIORITY ROADMAP

### High Priority (Core Quality & Stability)

### Medium Priority (User Experience)
- **Progress System Integration**: Complete integration of enhanced progress system into CLI binaries (currently using old progress system)
- **Beautiful Shadows Listing**: Make shadows listing output beautiful and user-friendly
- **General UI/UX Polish**: General UI polish and UX improvements across all commands

### Release Preparation
- **Security Audit**: Comprehensive security audit of cryptographic implementation and data handling
- **Software Architecture Audit**: Review architectural decisions and domain modeling for production readiness
- **Test Coverage Audit**: Audit test implementation and coverage to ensure comprehensive validation
- **Production Release Plan**: Create comprehensive plan for production release preparation

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
