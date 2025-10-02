# Feature Backlog

> **High-level roadmap ordered by priority. When starting work on an item, create detailed implementation plan in `CURRENT_WORK.md`**

## 🎯 CURRENT WORK
- **Security Audit**: Thorough security review of cryptographic implementation and system design

## 📋 PRIORITY ROADMAP

1. **Code Quality Polish**: Apply clippy fixes, formatting, and documentation improvements (identified in audit)
2. **Production Readiness**: Comprehensive testing, documentation, and release preparation

## 🔧 FUTURE CONSIDERATIONS

- **Secure Viewing (`shadowview`)**: View encrypted files without persistent decryption
- **Secure Editing (`shadowedit`)**: Edit encrypted text files in-place
- **Post-Quantum Cryptography**: Future-proof encryption algorithms  
- **Cloud Storage Integration**: Seamless encrypted backup and sync
- **Streaming I/O Optimization**: Large file handling with chunked processing *(when needed)*

---

## Quality Audit Findings Integration

**Audit Outcome**: Shadow demonstrates **exceptional code quality** with production-ready architecture and minimal technical debt.

**Immediate Opportunities** (identified in Phase 21 audit):
- **Code Polish**: 44 clippy issues (mostly redundant closures, formatting)
- **Documentation**: Minor API documentation gaps
- **Security Enhancement**: Complete mlock implementation for secure memory

**Strategic Direction**: Focus shifted from major improvements to minor polish and production readiness, as audit confirmed excellent foundational quality.

---

## Backlog Management Notes

**Simple Priority Order**: Items are ordered by priority - work on the first item in the Priority Roadmap.

**Detailed Planning**: When starting work on an item, create `CURRENT_WORK.md` with:
- Problem analysis and research
- Implementation plan broken into steps
- Technical considerations and trade-offs
- Success criteria and testing approach

**Adaptation**: Priorities can be reordered based on:
- User feedback and changing requirements
- Technical discoveries during implementation
- Security considerations and dependencies
- Resource constraints and opportunities

**Completion**: When work is done, archive details to `CHANGELOG.md` and remove from backlog.
