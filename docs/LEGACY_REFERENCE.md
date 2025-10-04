# Legacy Code Reference Guide

This document provides guidance for using the preserved legacy implementation during the clean rewrite process.

## 📁 **Legacy Structure Overview**

All previous implementation preserved in `legacy/` folder with complete git history:

```
legacy/
├── Cargo.toml                    # Original dependencies and configuration
├── src/                          # Complete legacy implementation
│   ├── shared/                   # Core patterns to preserve and reimplement
│   │   ├── header.rs            # ⭐ TLV header system (V3 → V1 baseline)
│   │   ├── algorithms/          # ⭐ Crypto config providers and implementations
│   │   ├── core/                # Error handling, file detection, secure memory
│   │   └── versions/            # Version compatibility and migration logic
│   ├── encryption/              # File encryption implementations
│   ├── decryption/              # File decryption implementations
│   ├── listing/                 # Directory scanning and display
│   └── migration/               # Version migration implementations
└── tests/                       # Legacy integration tests (patterns for new tests)
```

## 🎯 **Key Assets for Reimplementation**

### **Critical Patterns to Preserve**

1. **TLV Header System** (`legacy/src/shared/header.rs`, `legacy/src/shared/versions/v3_tlv_poc.rs`)
   - Extensible Type-Length-Value field structure
   - Algorithm-agnostic design supporting variable nonce lengths
   - Unknown field preservation for forward compatibility
   - **Reimplement as V1 baseline** following `docs/specs/DOMAIN_ARCHITECTURE.md`

2. **Configuration Provider Pattern** (`legacy/src/shared/algorithms/config.rs`)
   - Trait-based dependency injection (`KeyDerivationConfig + EncryptionConfig`)
   - Test vs production parameter separation
   - Clean algorithm abstraction
   - **Preserve pattern exactly** as specified in domain architecture

3. **Version Compatibility Matrix** (`legacy/src/shared/versions/`)
   - Migration planning and safety checking
   - Capability matrix for version features
   - **Extend for V1 baseline** as new foundation version

4. **Cryptographic Implementations**
   - XChaCha20-Poly1305: `legacy/src/shared/algorithms/xchacha20_poly1305/`
   - AES-256-GCM: `legacy/src/shared/algorithms/aes_gcm/`
   - Key derivation with Argon2id
   - **Extract proven algorithms** for infrastructure layer

### **Quality Patterns to Reference**

1. **Error Handling** (`legacy/src/shared/core/errors.rs`)
   - User-friendly messages without sensitive details
   - Actionable guidance and hints
   - Security-conscious error design

2. **File Detection** (`legacy/src/shared/core/file_detection.rs`)
   - Magic number validation for encrypted files
   - Double-encryption prevention logic

3. **Secure Memory** (`legacy/src/shared/core/crypto/secure_memory.rs`)
   - Key material zeroization patterns
   - Timing-safe operations

4. **Progress Reporting** (`legacy/src/shared/progress.rs`)
   - Real-time progress feedback
   - Performance measurement

## 📋 **Implementation Strategy**

### **How to Use Legacy Code**

1. **Start with Specs**: Always begin implementation from `docs/specs/DOMAIN_ARCHITECTURE.md`
2. **Reference for Patterns**: Use legacy code to understand proven implementations
3. **Extract Selectively**: Copy useful patterns but adapt to new architecture
4. **Rewrite Cleanly**: Don't port directly - reimplement according to domain design
5. **Preserve Intent**: Keep the essence of excellent patterns while improving structure

### **Legacy → New Architecture Mapping**

| Legacy Location | New Implementation Target | Notes |
|----------------|---------------------------|-------|
| `legacy/src/shared/header.rs` | `src/infrastructure/crypto/` | TLV header system as V1 baseline |
| `legacy/src/shared/algorithms/` | `src/infrastructure/crypto/algorithms/` | Config providers + implementations |
| `legacy/src/encryption/` | `src/domain/services/encryption_service.rs` | Business logic extraction |
| `legacy/src/decryption/` | `src/domain/services/decryption_service.rs` | Business logic extraction |
| `legacy/src/listing/` | `src/domain/services/listing_service.rs` | Business logic extraction |
| `legacy/src/migration/` | `src/domain/services/migration_service.rs` | Business logic extraction |

### **Testing Strategy**

- **Legacy Tests**: Available in `legacy/tests/` for pattern reference
- **New Tests**: Create from scratch following clean architecture
- **Integration Patterns**: Extract test scenarios but rewrite for new structure

## ⚠️ **Important Guidelines**

1. **Don't Port Directly**: Legacy code uses different architecture - extract patterns, not code
2. **Follow Specs First**: Domain architecture specifications are the primary source of truth
3. **Preserve Excellence**: Keep what works well, improve what doesn't
4. **Clean Implementation**: New code should be cleaner and more maintainable than legacy
5. **Security Priority**: Maintain or improve security properties from legacy implementation

## 🔍 **Quick Reference Commands**

```bash
# Search for specific patterns in legacy code
grep -r "pattern" legacy/src/

# Find TLV header implementation
find legacy/src/ -name "*header*" -o -name "*tlv*"

# Locate configuration providers
find legacy/src/ -name "*config*"

# Find algorithm implementations
ls legacy/src/shared/algorithms/
```

---

**Remember**: Legacy code is a reference library, not a codebase to maintain. Use it to understand proven patterns, then implement those patterns cleanly in the new architecture.