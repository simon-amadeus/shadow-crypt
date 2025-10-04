# Current Development Cycle

## 🎯 **CYCLE OBJECTIVE**
**Complete Architecture Rewrite**: Move existing code to legacy/ folder and start from scratch based on docs/specs with clean new codebase aligned to target architecture

## 📋 **DETAILED PLAN**

### **Phase 1: Legacy Code Preservation**
**Objective**: Safely preserve existing implementation while preparing for clean rewrite
**Approach**: Move all current code to `legacy/` folder structure

**Actions:**
1. Create `legacy/` directory structure
2. Move all existing `src/` contents to `legacy/src/`
3. Move existing `tests/` to `legacy/tests/`
4. Update `Cargo.toml` to temporarily exclude legacy code from compilation
5. Preserve `legacy/Cargo.toml` with original dependencies for reference

**Success Criteria:**
- ✅ All existing code safely preserved in `legacy/` folder
- ✅ Main workspace compiles without errors (even if empty)
- ✅ No functionality loss (legacy code can be referenced when needed)
- ✅ Git history preserved for all moved files

### **Phase 2: Clean Architecture Foundation**
**Objective**: Establish new directory structure aligned with domain architecture specs
**Approach**: Create empty module structure following DOMAIN_ARCHITECTURE.md

**Actions:**
1. Create new `src/` structure with domain architecture layers:
   ```
   src/
   ├── lib.rs                          # Library root
   ├── main.rs                         # Default binary (shadow)
   ├── domain/                         # Domain Layer (Core)
   │   ├── mod.rs
   │   ├── entities/                   # Domain Entities
   │   │   ├── mod.rs
   │   │   ├── encrypted_file.rs       # EncryptedFile entity
   │   │   ├── plaintext_file.rs       # PlaintextFile entity
   │   │   ├── crypto_session.rs       # CryptoSession entity
   │   │   ├── duplicate_detector.rs   # DuplicateDetector entity
   │   │   └── file_metadata.rs        # FileMetadata entity
   │   ├── services/                   # Domain Services
   │   │   ├── mod.rs
   │   │   ├── encryption_service.rs   # EncryptionService
   │   │   ├── decryption_service.rs   # DecryptionService
   │   │   ├── listing_service.rs      # ListingService
   │   │   └── migration_service.rs    # MigrationService
   │   └── repositories/               # Repository Interfaces
   │       ├── mod.rs
   │       ├── file_repository.rs      # FileRepository trait
   │       └── password_repository.rs  # PasswordRepository trait
   ├── application/                    # Application Services Layer
   │   ├── mod.rs
   │   └── workflows/                  # Application Workflows
   │       ├── mod.rs
   │       ├── encryption_workflow.rs  # EncryptionWorkflow
   │       ├── decryption_workflow.rs  # DecryptionWorkflow
   │       ├── listing_workflow.rs     # ListingWorkflow
   │       └── migration_workflow.rs   # MigrationWorkflow
   ├── infrastructure/                 # Infrastructure Layer (I/O)
   │   ├── mod.rs
   │   ├── crypto/                     # Cryptographic Implementations
   │   │   ├── mod.rs
   │   │   ├── algorithms/             # Algorithm Implementations
   │   │   │   ├── mod.rs
   │   │   │   ├── xchacha20_poly1305.rs
   │   │   │   └── aes_256_gcm.rs
   │   │   ├── key_derivation.rs       # Argon2id implementation
   │   │   └── secure_memory.rs        # SecureBox and zeroization
   │   ├── file_system/                # File System Operations
   │   │   ├── mod.rs
   │   │   └── standard_file_repository.rs
   │   └── terminal/                   # Terminal/CLI Operations
   │       ├── mod.rs
   │       └── standard_password_repository.rs
   └── cli/                            # CLI Layer (Binaries)
       ├── mod.rs
       ├── shadow.rs                   # shadow binary
       ├── unshadow.rs                 # unshadow binary
       ├── shadows.rs                  # shadows binary
       └── shadowmigrate.rs            # shadowmigrate binary
   ```

2. Create minimal module declarations and placeholders
3. Update `Cargo.toml` with proper binary definitions
4. Ensure clean compilation with empty implementations

**Success Criteria:**
- ✅ Clean directory structure matches domain architecture specs
- ✅ All modules compile without errors (empty implementations)
- ✅ Binary targets properly defined in Cargo.toml
- ✅ Foundation ready for incremental implementation

### **Phase 3: Essential Dependencies Setup**
**Objective**: Define minimal, security-focused dependency list
**Approach**: Only include dependencies required for target architecture

**Actions:**
1. Update `Cargo.toml` with essential dependencies:
   - `chacha20poly1305` - XChaCha20-Poly1305 implementation
   - `aes-gcm` - AES-256-GCM implementation  
   - `argon2` - Key derivation
   - `rand` - Cryptographically secure random numbers
   - `zeroize` - Secure memory clearing
   - `thiserror` - Error handling
   - `clap` - CLI argument parsing
   - `tokio` - Async runtime (if needed)
   - `serde` - Serialization (for TLV headers)

2. Remove all legacy dependencies not needed for target architecture
3. Verify dependency compilation and basic imports

**Success Criteria:**
- ✅ Minimal dependency set supporting target architecture
- ✅ All dependencies compile successfully
- ✅ No unnecessary or legacy dependencies included
- ✅ Security-focused dependency selection completed

### **Phase 4: Validation & Testing Cleanup**
**Objective**: Remove legacy tests and prepare for new testing approach
**Approach**: Clean slate for testing aligned with new architecture

**Actions:**
1. Remove existing `tests/` directory (moved to `legacy/tests/`)
2. Create new `tests/` structure for integration tests:
   ```
   tests/
   ├── integration/
   │   ├── mod.rs
   │   ├── encryption_tests.rs
   │   ├── decryption_tests.rs
   │   └── end_to_end_tests.rs
   └── fixtures/
       └── test_files/
   ```

3. Verify cargo test runs cleanly (even with no tests)
4. Document testing strategy for next cycles

**Success Criteria:**
- ✅ Legacy tests safely preserved but not interfering
- ✅ Clean testing foundation ready for new architecture
- ✅ `cargo test` executes without errors
- ✅ Testing strategy documented for implementation

## 🎯 **SUCCESS CRITERIA SUMMARY**

### **Primary Objectives**
- ✅ **Clean Slate Achievement**: Complete separation from legacy code patterns
- ✅ **Architecture Alignment**: New structure matches domain architecture specs exactly
- ✅ **Compilation Success**: All empty modules compile without errors
- ✅ **Dependency Minimization**: Only essential, security-focused dependencies included

### **Quality Gates**
- ✅ **No Compilation Errors**: `cargo build` succeeds completely
- ✅ **No Test Failures**: `cargo test` runs cleanly
- ✅ **Spec Compliance**: Directory structure matches DOMAIN_ARCHITECTURE.md
- ✅ **Legacy Preservation**: All existing code safely accessible in `legacy/`

### **Risk Mitigation**
- ✅ **No Functionality Loss**: Legacy implementation preserved for reference
- ✅ **Incremental Progress**: Each phase can be validated independently
- ✅ **Rollback Capability**: Can restore legacy structure if needed
- ✅ **Documentation Sync**: All changes align with existing specs

## 📊 **ESTIMATED EFFORT**
- **Phase 1**: 30 minutes (file movement and structure)
- **Phase 2**: 45 minutes (module creation and organization)
- **Phase 3**: 30 minutes (dependency management)
- **Phase 4**: 15 minutes (test cleanup)
- **Total**: ~2 hours for complete foundation

## 🔍 **VALIDATION APPROACH**
1. **After each phase**: Verify compilation and basic structure
2. **Continuous validation**: Ensure specs alignment throughout
3. **Reference checking**: Compare against DOMAIN_ARCHITECTURE.md regularly
4. **Documentation updates**: Keep README.md in sync with changes

---

**Next Phases**: After successful completion, next cycle will implement core domain entities starting with TLV Header System V1 foundation.