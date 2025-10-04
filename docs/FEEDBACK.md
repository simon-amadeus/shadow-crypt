# Customer Feedback

Add your feedback here. Keep it simple - just write what you think.

---

## New Feedback

**2025-10-04 - Critical Architecture Violations in Algorithm Abstraction**: Current implementation violates clean architecture by placing domain abstractions (`CryptographicAlgorithm`, `AlgorithmId`, `KeyMaterial`) in infrastructure layer. Domain services import from infrastructure, breaking dependency inversion principle.

**Violations Identified**:
- `src/infrastructure/crypto/algorithms.rs` contains domain-level abstractions
- `src/domain/services/crypto_config.rs:6` imports `crate::infrastructure::crypto::errors::CryptoError`
- Duplicate `AlgorithmId` definitions in domain and infrastructure
- Core business traits living in infrastructure instead of domain

**Impact**: Breaks clean architecture, makes domain layer dependent on infrastructure, violates SOLID principles

**Required Action**: Comprehensive refactoring to move all cryptographic abstractions to domain layer, make infrastructure implement domain interfaces through dependency inversion

---

## Processed Feedback

- **2025-10-04**: Rewrite approach guidance - Move existing code to legacy/ folder, start from scratch based on docs/specs, remove old integration tests, focus on clean new codebase aligned to target architecture. → **Processed into backlog P0 item**