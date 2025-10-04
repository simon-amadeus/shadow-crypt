# Customer Feedback

Add your feedback here. Keep it simple - just write what you think.

---

## New Feedback

**2025-10-04 - Complete Crypto Infrastructure Implementation**: After architecture refactoring, infrastructure crypto implementations need completion to achieve full functionality. 

**Technical Requirements**:
- Fix return type mismatches: Infrastructure methods returning `CryptoError` need conversion to `DomainError` to match domain interfaces
- Align KeyMaterial interfaces: Domain expects 3-key constructor `new(master_key, encryption_key, obfuscation_key)`, infrastructure providing single key
- Standardize AlgorithmId naming: Infrastructure uses `Aes256Gcm`, domain uses `AesGcm256` - choose consistent naming
- Implement missing methods: Add `as_bytes()` method to domain KeyMaterial, implement `generate_nonce()` in infrastructure configs

**Implementation Context**: Clean architecture now properly established with zero domain→infrastructure imports. Core violation resolved, these are implementation details for full functionality.

**Root Cause**: Architecture migration prioritized layer separation over implementation compatibility, creating interface mismatches that need resolution.

**Priority**: P1 after current critical foundation items, needed for functional crypto operations

---

## Processed Feedback

- **2025-10-04**: Critical Architecture Violations in Algorithm Abstraction - Cryptographic abstractions incorrectly placed in infrastructure layer, violating clean architecture. Domain services importing from infrastructure breaks dependency inversion. Requires comprehensive refactoring to move all crypto abstractions to domain layer. → **Processed into backlog P0 item**
- **2025-10-04**: Rewrite approach guidance - Move existing code to legacy/ folder, start from scratch based on docs/specs, remove old integration tests, focus on clean new codebase aligned to target architecture. → **Processed into backlog P0 item**