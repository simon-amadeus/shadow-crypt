# Current Development Cycle

## 🎯 **OBJECTIVE**: Algorithm Abstraction Layer Implemen# Current Development Cycle

## 🎯 **OBJECTIVE**: Refactor Algorithm Abstraction Layer for Clean Architecture

**Goal**: Fix architectural violations by moving crucial cryptographic abstractions from infrastructure to domain layer

**Source**: User feedback - current implementation violates clean architecture principles

## 📋 **ARCHITECTURAL VIOLATIONS IDENTIFIED**

### **Primary Issues**
1. **CryptographicAlgorithm trait in infrastructure**: Core business abstraction lives in `src/infrastructure/crypto/algorithms.rs` instead of domain
2. **AlgorithmId duplication**: Two different definitions exist - one in domain (`crypto_session.rs`) and one in infrastructure (`algorithms.rs`)
3. **Domain importing infrastructure**: `src/domain/services/crypto_config.rs` imports `crate::infrastructure::crypto::errors::CryptoError`
4. **Algorithm enum in infrastructure**: The `Algorithm` enum factory pattern is in infrastructure but represents domain concepts
5. **KeyMaterial in infrastructure**: Core security primitive should be in domain layer

### **Architectural Requirements Violations**
According to `docs/specs/ARCHITECTURE_REQUIREMENTS.md`:
- **Clean Architecture**: Domain-driven design with dependency inversion ❌
- **Security First**: Core crypto abstractions should be in domain ❌  
- **Configuration Provider Pattern**: Currently tightly coupled to infrastructure ❌

## 🏗️ **REFACTORING PLAN**

### **Phase 1: Define Clean Domain Abstractions**
**Objective**: Create proper domain-layer cryptographic abstractions

**Steps**:
1. **Create `src/domain/services/crypto_algorithm.rs`**:
   - Move `CryptographicAlgorithm`, `KeyDerivationConfig`, `EncryptionConfig` traits to domain
   - Define clean interfaces without infrastructure dependencies
   - Create domain-specific error types

2. **Create `src/domain/entities/algorithm_id.rs`**:
   - Consolidate the two `AlgorithmId` definitions into single domain entity
   - Include domain logic (name, key_size, nonce_size methods)
   - Remove infrastructure dependency

3. **Create `src/domain/entities/key_material.rs`**:
   - Move `KeyMaterial` from infrastructure to domain
   - Maintain security properties (zeroization)
   - Make it pure domain entity

### **Phase 2: Update Domain Layer**
**Objective**: Remove all infrastructure dependencies from domain

**Steps**:
1. **Update `src/domain/services/crypto_config.rs`**:
   - Remove `use crate::infrastructure::crypto::errors::CryptoError`
   - Use domain error types instead
   - Keep trait definitions but make them infrastructure-agnostic

2. **Update `src/domain/entities/crypto_session.rs`**:
   - Use domain `AlgorithmId` (remove local definition)
   - Use domain `KeyMaterial`
   - Reference domain crypto traits

3. **Create domain error types**:
   - Add cryptographic error variants to `src/domain/errors.rs`
   - Ensure no infrastructure coupling

### **Phase 3: Create Infrastructure Adapters**
**Objective**: Implement domain abstractions in infrastructure layer

**Steps**:
1. **Update `src/infrastructure/crypto/algorithms.rs`**:
   - Implement domain traits for infrastructure types
   - Remove domain-level abstractions (they now live in domain)
   - Create adapters that bridge domain and implementation

2. **Update `src/infrastructure/crypto/factory.rs`**:
   - Make `Algorithm` enum implement domain traits
   - Remove domain logic, focus on implementation selection
   - Maintain factory pattern but as infrastructure concern

3. **Update concrete implementations**:
   - Make `XChaCha20Poly1305Config` and `Aes256GcmConfig` implement domain traits
   - Remove infrastructure-specific details from domain interface

### **Phase 4: Update Dependencies**
**Objective**: Ensure clean dependency flow

**Steps**:
1. **Application layer updates**:
   - Import domain traits instead of infrastructure
   - Use dependency injection with domain interfaces

2. **CLI layer updates**:
   - Depend only on application and domain layers
   - Infrastructure wired through dependency injection

3. **Test updates**:
   - Update integration tests to use domain abstractions
   - Maintain infrastructure-specific unit tests

### **Phase 5: Validation & Cleanup**
**Objective**: Ensure architectural compliance

**Steps**:
1. **Dependency validation**:
   - Verify no domain → infrastructure imports
   - Confirm dependency inversion principle
   - Check application → domain flow

2. **Test validation**:
   - All existing functionality preserved
   - Tests compile and pass
   - Integration tests work with new architecture

3. **Documentation update**:
   - Update specs to reflect clean architecture
   - Document new trait locations
   - Verify alignment with architectural requirements

## 🔍 **VALIDATION CRITERIA**

### **Architecture Compliance**
- [ ] No `use crate::infrastructure` imports in domain layer
- [ ] All crypto abstractions (`CryptographicAlgorithm`, `AlgorithmId`, `KeyMaterial`) in domain
- [ ] Infrastructure implements domain traits (dependency inversion)
- [ ] Clean separation of concerns

### **Functional Validation**
- [ ] All existing tests pass
- [ ] Algorithm factory pattern still works
- [ ] XChaCha20-Poly1305 and AES-256-GCM implementations functional
- [ ] Cross-algorithm compatibility maintained

### **Security Validation**
- [ ] Key material zeroization preserved
- [ ] Secure memory management intact
- [ ] No regression in cryptographic security

## 📚 **REFERENCES**

**Architecture Requirements**: `docs/specs/ARCHITECTURE_REQUIREMENTS.md`
- Layered architecture with proper dependency flow
- Clean architecture with domain-driven design
- Configuration provider pattern preservation

**Current Violations**:
- `src/domain/services/crypto_config.rs:6` - imports infrastructure
- `src/domain/entities/crypto_session.rs` - local AlgorithmId instead of domain entity
- `src/infrastructure/crypto/algorithms.rs` - contains domain abstractions

**Target State**: 
- Domain contains all business abstractions
- Infrastructure implements domain interfaces  
- Application orchestrates through domain abstractions
- No upward dependencies in architectureoal**: Implement XChaCha20-Poly1305 (default) + AES-256-GCM with pluggable cryptographic interface

**Source**: P0 priority from backlog - foundational security requirement

## 📋 **SUCCESS CRITERIA**

1. **Abstraction Interface**: Clean `CryptoAlgorithm` trait with encrypt/decrypt operations
2. **XChaCha20-Poly1305**: Full implementation as default algorithm (legacy reference: `legacy/src/shared/algorithms/xchacha20_poly1305/`)
3. **AES-256-GCM**: Alternative implementation (legacy reference: `legacy/src/shared/algorithms/aes_gcm/`)
4. **Algorithm Registry**: Pluggable system for algorithm selection by ID
5. **Integration**: Works with domain layer `EncryptedFile` entity
6. **Security**: Proper random nonce generation, key derivation, authenticated encryption
7. **Tests**: Comprehensive unit tests + compatibility validation with legacy format
8. **Error Handling**: Secure, user-friendly error messages

## 🔧 **IMPLEMENTATION APPROACH**

### Phase 1: Core Trait Design
- Define `CryptoAlgorithm` trait in `src/domain/services/crypto/`
- Specify operations: encrypt, decrypt, key derivation, nonce generation
- Design `AlgorithmId` enum and registry pattern
- Reference specs: `docs/specs/DOMAIN_ARCHITECTURE.md` entity patterns

### Phase 2: XChaCha20-Poly1305 Implementation  
- Implement in `src/domain/services/crypto/algorithms/xchacha20_poly1305.rs`
- Use chacha20poly1305 crate (already in Cargo.toml)
- Reference working pattern: `legacy/src/shared/algorithms/xchacha20_poly1305/mod.rs`
- Focus on: key derivation (Argon2), nonce generation, authenticated encryption

### Phase 3: AES-256-GCM Implementation
- Implement in `src/domain/services/crypto/algorithms/aes_gcm.rs` 
- Use aes-gcm crate (already in Cargo.toml)
- Reference working pattern: `legacy/src/shared/algorithms/aes_gcm/mod.rs`
- Ensure compatibility with XChaCha20 interface

### Phase 4: Algorithm Registry
- Create `src/domain/services/crypto/registry.rs`
- Enable runtime algorithm selection by ID
- Default to XChaCha20-Poly1305, support AES-256-GCM
- Support for future algorithm additions

### Phase 5: Integration & Testing
- Unit tests for each algorithm implementation
- Cross-compatibility tests (encrypt with one, decrypt with other using same interface)
- Legacy format compatibility validation
- Performance benchmarking (basic)

## 🔍 **VALIDATION PLAN**

### Technical Validation
- [ ] All algorithms implement `CryptoAlgorithm` trait correctly
- [ ] XChaCha20-Poly1305 encrypts/decrypts successfully 
- [ ] AES-256-GCM encrypts/decrypts successfully
- [ ] Registry correctly selects algorithms by ID
- [ ] Legacy compatibility: can decrypt files created by legacy implementation
- [ ] Security: proper nonce handling, no key material leakage
- [ ] Error handling: user-friendly messages, no sensitive data exposure

### Integration Validation  
- [ ] `EncryptedFile` entity can use both algorithms
- [ ] HeaderV1 format correctly stores algorithm ID
- [ ] File round-trip: create → save → load → decrypt → verify
- [ ] Cross-algorithm compatibility via registry

## 📚 **CONTEXT & REFERENCES**

**Primary Specs**:
- `docs/specs/DOMAIN_ARCHITECTURE.md`: Entity design patterns
- `docs/specs/ARCHITECTURE_REQUIREMENTS.md`: Security requirements

**Legacy References**:
- `legacy/src/shared/algorithms/xchacha20_poly1305/mod.rs`: Working XChaCha20 implementation
- `legacy/src/shared/algorithms/aes_gcm/mod.rs`: Working AES-GCM implementation  
- `legacy/src/shared/algorithms/config.rs`: Algorithm configuration patterns
- `legacy/src/shared/core/errors.rs`: Error handling patterns

**Dependencies**: Already available in current Cargo.toml
- chacha20poly1305 = "0.10"
- aes-gcm = "0.10" 
- argon2 = "0.5"
- rand = "0.8"

## � **DISCOVERY**

**Issue Identified**: The planned work item "Algorithm Abstraction Layer" was already completed in v0.6.0 (2025-10-04)

**Evidence**: 
- Complete implementation exists in `src/infrastructure/crypto/`
- Comprehensive tests in `tests/crypto_abstraction_integration.rs`
- Documented in CHANGELOG.md v0.6.0 section
- Both XChaCha20-Poly1305 and AES-256-GCM fully implemented with pluggable interface

**Resolution**: Need to update backlog and move to next priority item.
