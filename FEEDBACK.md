# Customer Feedback

Add your feedback here. Keep it simple - just write what you think.

---

## New Feedback

*(Add new items here)*

---

## Addressed

### October 1, 2025 - Critical Versioning Architecture Foundation

- **ROADMAP UPDATED**: Critical Versioning Architecture Issues for Migration System
  - **Status**: Integrated into roadmap as new Phase 9.991 (Critical versioning architecture foundation)
  - **Priority**: URGENT - Takes precedence over security hardening due to fundamental architectural issues
  - **Action**: Created comprehensive versioning architecture phase focusing on proper version-specific types, migration chains, and compatibility matrices
  - **Impact**: Establishes proper foundation for robust migration system that can handle different file format versions correctly

**Versioning Architecture Integration Summary:**
1. **Versioned types implementation** - Distinct types for each format version (HeaderV1, HeaderV2, etc.)
2. **Version-specific serialization** - Each version has its own parsing/serialization logic
3. **Migration type conversion** - Proper conversion between distinct version types
4. **Compatibility matrix** - Define precise version compatibility rules
5. **Format vs. feature separation** - Distinguish file format versions from software versions
6. **Trait-based handlers** - Type-safe version implementations with proper migration chains

### October 1, 2025 - Urgent Code Refactoring and Structure Cleanup

- **ROADMAP UPDATED**: urgent!: refactor the code. reduce file size and complexity. make a plan to improve the structure and clean up so that new features or changes can be added more easily.
  - **Status**: Integrated into roadmap as new Phase 9.99 (Critical code refactoring and structure cleanup)
  - **Priority**: URGENT - Takes precedence over security hardening due to customer feedback
  - **Action**: Created comprehensive refactoring phase focusing on module size reduction, complexity simplification, and maintainability improvements
  - **Impact**: Establishes foundation for easier future development and maintenance

- **ROADMAP UPDATED**: at some point: finish secure memory implementation
  - **Status**: Integrated into Phase 9.9 (Critical security hardening) 
  - **Action**: Added secure memory completion as medium priority security enhancement
  - **Impact**: Ensures comprehensive secure memory handling for sensitive data

**Refactoring Integration Summary:**
1. **Module decomposition** - Reduce file sizes by 30-50% through focused single-responsibility components
2. **Complexity reduction** - Simplify overly complex functions and improve maintainability
3. **Architecture optimization** - Streamline module boundaries and reduce coupling
4. **Future-proofing** - Create clear extension points and plugin architecture foundation
5. **Dependency chain update** - Phase 9.9 security hardening now depends on Phase 9.99 completion

### September 30, 2025 - Project Rebranding to "Shadow"

- **ROADMAP UPDATED**: Complete project rebranding from "crypto" to "shadow" with enhanced user experience
  - **Status**: Integrated into roadmap as new Phase 9.95 (Critical branding update)
  - **Action**: Created comprehensive rebranding phase covering commands, file formats, and documentation
  - **Impact**: Addresses user feedback for better branding with "shadow" metaphor

**Integrated Branding Changes:**
1. **Command rebranding** - `lock`→`shadow`, `unlock`→`unshadow`, `cryptls`→`shadows`, etc.
2. **File format updates** - Magic bytes `CRYPTO`→`SHADOW`, extension `.enc`→`.shadow`
3. **Backward compatibility** - Legacy file support during transition
4. **Documentation updates** - Complete rebranding across all materials

### September 30, 2025 - Future Migration System for Cryptographic Agility

- **ROADMAP UPDATED**: Migration system foundation for cryptographic agility and future algorithm upgrades
  - **Status**: Integrated into roadmap as new Phase 9.98 (Migration system foundation)
  - **Action**: Created comprehensive migration infrastructure phase with safety features
  - **Impact**: Addresses user request for future-proofing and cryptographic agility

**Integrated Migration Features:**
1. **Version detection** - Proper header versioning starting with version 1
2. **Migration tool architecture** - `shadowmigrate` command design
3. **Algorithm transition support** - Infrastructure for future upgrades
4. **Safety features** - Backup, verification, and rollback capabilities

### September 30, 2025 - Comprehensive Security Assessment

- **ROADMAP UPDATED**: Critical security hardening actions identified and prioritized
  - **Status**: Integrated into roadmap as new Phase 9.9 (Critical Security Hardening)
  - **Action**: Created focused high-priority phase to address security assessment findings
  - **Impact**: Addresses comprehensive security review recommendations for production-grade cryptographic software

**Security Actions Integrated:**
1. **Timing attack testing** - Statistical analysis with `dudect`
2. **Cryptographic fuzzing** - Edge case testing with `honggfuzz`  
3. **Filename authentication** - HMAC protection against substitution attacks
4. **Nonce reuse detection** - AES-GCM catastrophic failure prevention
5. **Error message security** - Prevent timing/oracle information leakage
6. **Resource exhaustion protection** - DoS attack prevention

**Assessment Summary**: Excellent security foundation (8.5/10) with clear path to production-grade cryptographic software quality through targeted security hardening.

### September 30, 2025 - Comprehensive Code Quality Assessment

- **ROADMAP UPDATED**: Medium priority code quality issues identified and prioritized
  - **Status**: Integrated into roadmap as new Phase 9.75 (Code Quality Improvements)
  - **Action**: Created focused phase to address excessive unwrap() usage, improve error handling, and enhance CLI input validation
  - **Impact**: Addresses quality assessment recommendations for production-ready error handling

**Quality Issues Addressed in Roadmap:**
1. **Excessive `unwrap()` usage** - Found 47 instances, especially in production code like `src/bin/lock.rs:40`
2. **Missing error propagation** - CLI argument handling could be more robust  
3. **Input validation** - Need comprehensive validation for CLI arguments

**Assessment Summary**: High-quality cryptographic application (B+ to A-) with excellent security foundation. Main issue is error handling which is easily addressable.

*(Completed items move here)*

### September 30, 2025 - Source File Removal Priority

- **ROADMAP UPDATED**: separate source file removal from the phase that implements multi-file support. source file removal is a generally useful feature that should be available for single-file operations as well. it is also more important than multi-file support, so it should be implemented first.
  - **Status**: Integrated into roadmap restructure - Phase 9 now focuses on source removal for single-file operations
  - **Action**: Reprioritized phases: Phase 9 = source removal, Phase 10 = multi-file encryption, Phase 11 = multi-file decryption
  - **Impact**: Addresses user insight that source removal is more generally useful and important

### September 30, 2025 - Multi-file Enhancement and Security Priorities

- **ROADMAP UPDATED**: add some option to remove the source file after encryption/decryption. maybe use --inplace or --remove-source flag? not sure about the name.
  - **Status**: Integrated into Phase 9 and 10 as `--remove-source`/`--inplace` flag feature
  - **Action**: Added to multi-file encryption/decryption tasks with safety considerations

- **ROADMAP UPDATED**: a strong security audit is requested ASAP.
  - **Status**: Integrated as new Phase 10.5 with high priority
  - **Action**: Created comprehensive security audit phase with external review and penetration testing

### September 21, 2025 - Roadmap Simplification

- **ROADMAP UPDATED**: the planned directory support for recursive encryption/decryption will never be needed.
  - **Status**: Integrated into roadmap - directory phases removed/postponed
  - **Action**: Focused roadmap on single/multi-file operations instead of directory recursion

### Phase 8.5 Roadmap Integration (September 21, 2025)

- **ROADMAP UPDATED**: the list in cryptls only shows the original filenames but not which obfuscated name corresponds to which original name. so when a user wants to decrypt a specific file they can't tell which obfuscated filename to use. the list should show both the obfuscated filename and the original filename (if it can be decrypted with the provided password). if the original filename can't be decrypted (wrong password or corrupted) it should indicate that as well.
  - **Status**: Integrated into roadmap as Phase 8.5 priority
  - **Action**: Created new priority phase for enhanced cryptls display

- **ROADMAP UPDATED**: overriding files should generally only be allowed with an explicit --force flag
  - **Status**: Integrated into roadmap as Phase 8.5 priority  
  - **Action**: Added --force flag requirement to Phase 8.5 tasks