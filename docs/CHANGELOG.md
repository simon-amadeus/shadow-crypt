# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Multi-file encryption and decryption support
- File viewing and editing tools
- External professional security audit

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
- `lock input.txt output.txt.enc` → `lock input.txt` (auto-creates `input.txt.enc`)
- `unlock file.enc output.txt` → `unlock file.enc` (auto-restores original filename)
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
- **Before**: `lock input.txt output.txt.enc` 
- **After**: `lock input.txt` → auto-creates `input.txt.enc`

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
