# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.991] - 2025-10-01

### Added - Critical Versioning Architecture Foundation (Phase 9.991 Complete)
- **Versioned Types System**: Implemented `VersionedHeader` trait with type-safe version handling
- **HeaderV1 Implementation**: Version-specific header type with dedicated serialization/deserialization
- **Version Detection**: Robust version detection from raw header data with proper error handling
- **Migration Type System**: `VersionMigrator` with type-safe migration planning and validation
- **Compatibility Matrix**: Comprehensive version compatibility checking and migration path planning
- **Version Dispatch**: `AnyHeader` enum providing unified interface with automatic version routing
- **Integration Testing**: Complete test suite validating versioning system functionality

### Changed - Migration System Architecture
- **File Analyzer**: Updated to use new versioning system with `detect_version` and `AnyHeader`
- **Migration Planner**: Enhanced to use `VersionMigrator` for compatibility validation
- **Version Constants**: Centralized version management through `algorithms` module
- **Type Safety**: Migration operations now use distinct types instead of version number updates

### Technical Details
- **Trait-Based Design**: `VersionedHeader` trait ensures type-safe version implementations
- **Version-Specific Logic**: Each version has dedicated parsing, validation, and serialization
- **Migration Chains**: Foundation for complex multi-step migrations between versions
- **Forward Compatibility**: Architecture ready for seamless addition of future versions
- **Error Handling**: Comprehensive error handling with detailed version validation messages

### Development Insights
- **Type Safety First**: Distinct types for each version prevent migration logic errors
- **Separation of Concerns**: Clear distinction between file format versions and software versions
- **Migration Foundation**: Proper architecture enables robust version transitions
- **Extensibility**: Plugin-ready architecture for future algorithm and format additions

### Roadmap Updates
- **COMPLETED**: Phase 9.991 Critical Versioning Architecture Foundation
- **NEXT PRIORITY**: Phase 9.9 Critical Security Hardening with proper versioning foundation

## [0.9.99] - 2025-10-01

### Changed - Critical Code Refactoring and Structure Cleanup (Phase 9.99 Complete)
- **BREAKING**: Major refactoring of header module structure for improved maintainability
- **Module Decomposition**: Split 1002-line `header.rs` into 4 focused modules:
  - `metadata.rs`: File metadata handling and serialization (~230 lines)
  - `algorithms.rs`: Algorithm identification and versioning (~80 lines)
  - `header_core.rs`: Main Header struct and serialization logic (~450 lines)
  - `header.rs`: Clean re-export interface for backward compatibility (~20 lines)
- **Architecture Optimization**: Reduced coupling between components with clear module boundaries
- **Code Complexity Reduction**: Applied single responsibility principle throughout header system
- **Future-Proofing**: Created clear extension points and plugin architecture foundation

### Technical Details
- **50%+ File Size Reduction**: Large monolithic module broken into manageable, focused components
- **Preserved Public API**: All existing functionality maintained through strategic re-exports
- **Enhanced Testability**: Each module can be tested and modified independently
- **Reduced Cognitive Overhead**: Clear separation of concerns improves code comprehension
- **Extension Ready**: Modular structure enables easy addition of new algorithms and metadata types

### Development Insights
- **Modular Architecture**: Breaking large files into focused modules dramatically improves maintainability
- **Backward Compatibility**: Strategic re-exports allow major internal restructuring without breaking existing code
- **Single Responsibility**: Each module now has a clear, testable purpose with minimal cross-dependencies
- **Future Development**: Foundation established for rapid addition of new features and improvements

### Roadmap Updates
- **COMPLETED**: Phase 9.99 Critical Code Refactoring and Structure Cleanup
- **NEXT PRIORITY**: Phase 9.9 Critical Security Hardening for production readiness

## [0.9.98] - 2025-09-30

### Added - Migration System Foundation (Phase 9.98 Complete)
- **Migration Infrastructure**: Comprehensive migration system for future Shadow file format versions
- **Version Management**: Standardized version 1 as current Shadow format with proper compatibility checking
- **Migration Tool**: New `shadowmigrate` binary for analyzing files and planning migrations
- **Safety Systems**: Backup creation, verification processes, and rollback capabilities
- **Cryptographic Agility**: Infrastructure foundation for future algorithm transitions

### Changed
- **Header Versioning**: Updated to use structured version constants (CURRENT_VERSION = 1)
- **Version Validation**: Enhanced with forward/backward compatibility boundaries
- **Module Organization**: Added migration module to shared components

### Technical Details
- Migration system can analyze individual files and directories for version compatibility
- Safety checks include file integrity, disk space, permissions, and decryption testing
- Migration planning estimates required steps and resources
- Designed for future algorithm transitions with structured migration paths
- Complete test coverage including integration tests for migration functionality

### Development Insights
- **Infrastructure First**: Building migration capability before needing it enables smooth transitions
- **Safety-Focused Design**: Multiple verification layers prevent data loss during migrations
- **Structured Analysis**: Systematic file analysis supports batch operations and planning
- **Future Algorithm Support**: Architecture ready for cryptographic algorithm evolution

### Roadmap Updates
- **COMPLETED**: Phase 9.98 Migration System Foundation
- **NEXT PRIORITY**: Phase 9.9 Critical Security Hardening for production readiness

## [0.9.95] - 2025-09-30

### Added - Project Rebranding to "Shadow" (Phase 9.95 Complete)
- **BREAKING**: Complete project rebranding from "crypto" to "shadow"
- New shadow-branded binaries: `shadow`, `unshadow`, `shadows`, `shadowview`, `shadowedit`
- Updated file format: Magic bytes changed from `ENC3` (4 bytes) to `SHADOW` (6 bytes)
- Updated header structure: Increased from 38 to 40 bytes to accommodate new magic bytes
- File extension changed from `.enc` to `.shadow` throughout system

### Changed
- **Cargo.toml**: Updated package name and all binary definitions to shadow branding
- **File detection**: Updated magic byte detection logic for new `SHADOW` format
- **Documentation**: Comprehensive update of all docs to reflect shadow branding
- **Test suite**: Updated all tests to use new magic bytes and file extensions
- **CLI help text**: Updated all command descriptions and examples

### Technical Details
- Header format migration preserves all functionality while updating branding
- Backward compatibility maintained through version field detection
- Complete test coverage for new file format including doctests
- All 47 test cases pass with new shadow-branded implementation

### Development Insights
- **Text replacement challenges**: Aggressive find/replace operations (`sed`) caused unintended field name corruption (e.g., "encryption" → "shadowryption")
- **Documentation coherence**: Complete rebranding requires systematic updates across code, tests, and documentation
- **Magic byte sizing**: Expanding from 4-byte to 6-byte magic bytes requires careful header size recalculation and test updates
- **Test reliability**: Doctests provide additional validation layer beyond unit and integration tests
- **Branding impact**: Complete rebranding affects binary names, file extensions, magic bytes, documentation, and user-facing text

### Roadmap Updates
- **NEW**: Added Phase 9.95 for complete "Shadow" rebranding based on user feedback
- **NEW**: Added Phase 9.98 for migration system foundation to enable cryptographic agility
- Reprioritized phases to complete branding first, then security hardening
- Updated command names: `lock`→`shadow`, `unlock`→`unshadow`, `cryptls`→`shadows`, etc.
- Updated file format: `.enc`→`.shadow`, magic bytes `CRYPTO`→`SHADOW`

## [0.9.8] - 2025-09-30

### Removed
- **CLEANUP**: Removed directory encryption/decryption modules - Dropped planned feature that was never needed
- Cleaned up codebase by removing `encrypt_directory.rs` and `decrypt_directory.rs` modules
- Updated documentation and error messages to reflect focus on individual file operations
- Maintained backward compatibility - existing file format and cryptls directory listing unchanged

### Changed
- Updated error messages to clarify support for individual files only
- Simplified module structure by focusing on core file encryption/decryption

## [0.9.7] - 2025-09-30

### Changed
- **CRITICAL**: Eliminated all production `unwrap()` calls in binary tools - Replaced with proper error handling and user-friendly error messages
- Enhanced input validation in `lock` and `unlock` binaries - Added file type checking and permission validation
- Improved CLI argument parsing robustness - Better error messages for invalid inputs
- Enhanced error handling for edge cases - Graceful handling of invalid file paths and permission issues

### Fixed
- Production code no longer uses `unwrap()` - Prevents potential panics in user-facing tools
- Added comprehensive file validation - Tools now properly reject directories and invalid file types
- Improved user experience with better error messages - Clear, actionable error messages for common issues

## [0.9.6] - 2025-09-30

### Fixed
- **CRITICAL**: Integration test performance optimization - Tests now complete in <5 seconds instead of 60+ seconds  
- **CRITICAL**: Fixed parameter mismatch between encryption and decryption in integration tests
- Added `encrypt_single_file_with_params` and `decrypt_single_file_with_params` functions for test parameter control
- All integration tests now use consistent lightweight Argon2 test parameters (1MB memory, 1 iteration)
- Systematic fix across all test files: `decryption_integration.rs`, `encryption_integration.rs`, `source_removal_integration.rs`, `listing_integration.rs`
- Production mode maintains security with system-adaptive parameters (32MB-512MB memory, 5 iterations, 1-8 threads)

### Changed
- `Argon2Params::default()` now automatically detects test vs production mode via `cfg!(test)`
- Added `Argon2Params::test_params()` and `Argon2Params::production_params()` methods
- Enhanced security validation tests to verify both parameter profiles

## [0.9.5] - 2025-09-30

### Added
- Comprehensive internal security audit with detailed report
- Adaptive Argon2id parameters based on actual system memory and CPU detection
- Constant-time cryptographic operations for filename obfuscation verification
- Security validation test suite with 5 specialized security tests
- Automated security audit script (`security_audit.sh`) for ongoing validation

### Security
- **MAJOR**: System-aware Argon2 memory cost (1/8 of available RAM, 32MB-512MB bounds)
- **MAJOR**: Actual CPU detection for optimal Argon2 parallelism (1-8 threads)
- **MEDIUM**: Constant-time comparison prevents timing side-channel attacks
- Security audit report identifies no critical or high-risk vulnerabilities
- Comprehensive dependency security analysis
- Memory safety validation and timing attack resistance verification

### Fixed
- Unused import warnings in `cryptview` and `cryptedit` binaries
- Hardcoded system resource parameters replaced with dynamic detection

### Changed
- Argon2 parameters now adapt to system capabilities automatically
- Enhanced cryptographic security with timing attack protections

## [0.9.0] - 2025-09-30

### Added
- Source file removal with `--remove-source`, `--inplace`, and `-r` flags
- Secure file deletion with random data overwriting before removal
- Safety confirmation prompts for destructive operations
- Atomic operations ensuring encryption/decryption success before source removal

### Changed
- **BREAKING**: Simplified CLI interface - removed output file arguments
- `lock input.txt output.txt.shadow` → `shadow input.txt` (auto-creates `input.txt.shadow`)
- `unlock file.shadow output.txt` → `unshadow file.shadow` (auto-restores original filename)
- Much more intuitive user experience with smart defaults

### Security
- Enhanced secure file deletion prevents data recovery
- Confirmation prompts prevent accidental data loss

## [0.8.5] - 2025-09-21

### Added
- Enhanced `cryptls` display showing both obfuscated and original filenames
- File overwrite protection requiring `--force` flag for intentional overwrites
- Visual status indicators in file listings

### Fixed
- Users can now map obfuscated filenames to original names in `cryptls` output
- Prevention of accidental file overwrites

## [0.8.0] - 2025-09-20

### Added
- `cryptls` tool for listing encrypted files in directories
- Directory scanning with magic number detection
- Encrypted file metadata extraction and display

## [0.7.0] - 2025-09-19

### Added
- Intelligent filename restoration during decryption
- Automatic original filename recovery from encrypted headers
- Fallback naming strategies for corrupted headers

## [0.6.0] - 2025-09-18

### Added
- Reversible filename obfuscation for privacy
- Collision-resistant obfuscated filename generation
- `--obfuscate` flag for `lock` binary

### Security
- Filename privacy protection against directory listing attacks

## [0.5.0] - 2025-09-17

### Added
- Complete file decryption functionality
- `unlock` binary for decrypting files
- Integrity verification during decryption
- Comprehensive error handling and user guidance

## [0.4.0] - 2025-09-16

### Added
- Single file encryption functionality
- `lock` binary for encrypting files
- Metadata preservation (permissions, timestamps, file hashes)
- Atomic file writing with error recovery

## [0.3.0] - 2025-09-15

### Added
- AES-256-GCM authenticated encryption implementation
- Argon2id password-based key derivation
- Secure random key and salt generation
- HKDF key derivation for file-specific keys
- Secure memory handling with automatic zeroization

### Security
- Industry-standard cryptographic primitives
- Memory safety with SecretVec implementation

## [0.2.0] - 2025-09-14

### Added
- Complete file header format with serialization/deserialization
- Magic number validation for encrypted file detection
- Comprehensive metadata structure for file attributes
- Algorithm agility support for future upgrades

## [0.1.0] - 2025-09-13

### Added
- Initial project structure with vertical slicing architecture
- Separate binaries: `lock`, `unlock`, `cryptls`, `cryptview`, `cryptedit`
- Modular design with shared cryptographic library
- Comprehensive test framework setup

---

*For future development plans, see [ROADMAP.md](ROADMAP.md)*
**Core functionality** - Single file decryption, integrity verification, error handling

### ✅ Phase 6: Filename Obfuscation (Completed)
**Privacy feature** - Reversible filename obfuscation, collision resistance

### ✅ Phase 7: Filename Restoration (Completed)
**Privacy feature** - Intelligent filename restoration from headers during decryption

### ✅ Phase 8: File Listing (Completed)
**Utility feature** - `cryptls` tool for scanning and listing encrypted files

### ✅ Phase 8.5: Critical UX Fixes (Completed)
**User feedback integration** - Enhanced file listing display, overwrite protection with `--force`

### ✅ Phase 9: Source Removal + CLI Simplification (September 30, 2025)
**Major UX improvement** - `--remove-source`/`--inplace` flags, simplified CLI interface

**Key Achievement**: Removed confusing output file arguments
- **Before**: `lock input.txt output.txt.shadow` 
- **After**: `shadow input.txt` → auto-creates `input.txt.shadow`

**Features**: Secure deletion, confirmation prompts, atomic operations

## 📊 Current Capabilities

### ✅ Working Tools
- **`lock`** - File encryption with optional filename obfuscation and source removal
- **`unlock`** - File decryption with automatic filename restoration and source removal  
- **`cryptls`** - Encrypted file listing with enhanced display

### ✅ Core Features
- **AES-256-GCM** authenticated encryption
- **Argon2id** password-based key derivation
- **Filename obfuscation** with collision resistance
- **Automatic filename restoration** from headers
- **Secure source file deletion** with random overwriting
- **File overwrite protection** with `--force` flag
- **Simplified CLI** with smart defaults

### 🏗️ Architecture
- **Vertical slicing** by use case (separate binaries)
- **Shared cryptographic library** with secure primitives
- **Comprehensive error handling** and user guidance
- **Test-driven development** with extensive coverage

## 🔧 Technical Status

- **Build**: ✅ Clean compilation, no warnings
- **Tests**: ✅ 65+ unit tests, 4 integration test suites  
- **Security**: ✅ Industry-standard cryptography, secure memory handling
- **Performance**: ✅ Efficient single-file operations
- **Documentation**: ✅ Complete API docs and user guides

## 🎯 What's Next

**Immediate**: Phase 9.5 - Security audit (user-requested priority)  
**Upcoming**: Multi-file support, viewing/editing tools, performance optimization

---

*For future development plans, see [ROADMAP.md](ROADMAP.md)*
