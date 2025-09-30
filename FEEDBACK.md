# Customer Feedback

Add your feedback here. Keep it simple - just write what you think.

---

## New Feedback

*(Add new items here)*

---

## Addressed

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