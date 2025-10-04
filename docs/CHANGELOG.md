# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2025-10-04

### Added
- **Comprehensive Error Handling Framework**: Security-conscious, user-friendly error system with actionable guidance across all layers
- **Domain Error Types**: Complete taxonomy covering cryptographic, file system, security, input validation, resource, and configuration errors
- **Infrastructure Error Integration**: Layer-specific errors for file system, terminal, crypto providers, serialization with proper error conversion chains
- **Application Error Coordination**: Workflow orchestration, service coordination, and validation errors with severity levels and recovery indicators
- **CLI Error Presentation**: Professional user-facing error messages with consistent formatting, exit codes, and actionable suggestions
- **Security-Conscious Design**: No sensitive information leakage, proper context preservation, and security-related error identification
- **Comprehensive Testing**: 65 unit tests covering all error scenarios, propagation patterns, user-friendly messages, and security validation

### Changed
- **Error Architecture**: Established layered error handling with clean propagation from domain through infrastructure, application, to CLI layers
- **User Experience**: All error messages now provide clear, actionable guidance with specific suggestions for resolution
- **Security Standards**: Error handling follows security-first principles with no cryptographic material or sensitive details exposed

### Technical Details
- **Exit Code Standards**: Proper CLI exit codes (authentication=2, file=3, input=4, security=5, resource=6, config=7, cancelled=130)
- **Error Severity Levels**: Warning, Error, Critical classification for appropriate user interface presentation
- **Recovery Indicators**: Automatic detection of recoverable vs non-recoverable errors for user guidance
- **Conversion Patterns**: Seamless error conversion between layers with context preservation and type safety

## [0.3.0] - 2025-10-04

### Added
- **Version Compatibility Matrix**: Complete future-proof migration system with V1 baseline and explicit compatibility checking
- **Migration Service**: Full migration orchestration with version transitions, safety checks, backup/restore functionality, and integrity verification
- **Version Management**: `VersionMatrix` with V3→V1 migration path, compatibility checking, and extensible design for future versions
- **Domain Integration**: `EncryptedFile` entity with version compatibility checking in file operations and migration status validation
- **Error Handling**: User-friendly migration error messages with actionable guidance and context-preserving error chain
- **Comprehensive Testing**: 20 tests covering version compatibility matrix, migration service functionality, domain integration, and future extensibility scenarios

### Changed
- **Domain Entities**: `EncryptedFile` now validates version compatibility during `from_file()` and `write_to_file()` operations
- **Architecture Foundation**: Established version compatibility as core infrastructure enabling safe format evolution
- **Migration Strategy**: Legacy V3 format can be read and migrated to V1 baseline, with no reverse migration for security

### Technical Details
- **V1 Baseline**: New format baseline derived from proven legacy V3 TLV structure
- **Migration Path**: V3→V1 header migration preserving TLV structure, requires password for decrypt/re-encrypt cycle
- **Safety Mechanisms**: Backup creation, integrity verification, atomic operations, and rollback on failure
- **Future Compatibility**: Unknown versions properly rejected, extensible matrix design for V2, V3+ additions

## [0.2.2] - 2025-10-04

### Added
- **Configuration Provider Pattern**: Trait-based dependency injection for clean algorithm abstraction with `KeyDerivationConfig`, `EncryptionConfig`, and `CryptoConfig` interfaces
- **XChaCha20-Poly1305 Provider**: Production-grade implementation with Argon2id key derivation, secure parameter validation, and factory pattern support
- **Cryptographic Infrastructure**: `CryptoError` enum with security-conscious error messaging and comprehensive error handling framework
- **Algorithm Abstraction**: Type-safe configuration composition enabling zero-cost runtime algorithm selection and polymorphic usage
- **Security Parameter Validation**: Industry-standard parameter enforcement with separate test/production configurations
- **Comprehensive Testing**: 10 tests covering trait implementation, provider patterns, dependency injection workflows, and security validation

### Changed
- **Domain Services**: Added crypto configuration module with clean interfaces for future cryptographic implementations
- **Infrastructure Layer**: Established crypto module structure with providers, errors, and extensible algorithm support

## [0.2.1] - 2025-10-04

### Added
- **TLV Header System V1**: Complete implementation of Type-Length-Value header system preserving proven V3 design patterns with V1 enhancements
- **Domain Entities**: `TlvHeader`, `TlvField`, `TlvFieldType` with clean API for header manipulation and metadata access
- **Infrastructure Support**: `TlvSerializer` with binary serialization/deserialization, error handling, and format validation  
- **Magic Number Validation**: `SHADOW01` magic number for file format detection and validation
- **Extensible Field System**: Support for original filename, content hash, algorithm ID, nonce, directory path, and custom attributes
- **Future Compatibility**: Unknown field types preserved during roundtrip operations for format evolution
- **Comprehensive Testing**: 18 tests covering domain model, infrastructure serialization, and integration workflows

### Changed
- **File Format**: Established V1 as new baseline format with deterministic field ordering and binary efficiency
- **Legacy Compatibility**: Maintains V3 TLV design patterns while adding V1-specific enhancements (content hash, dedicated nonce field)

### Technical Details
- **Domain Layer**: Clean architecture with domain entities independent of serialization concerns
- **Infrastructure Layer**: Binary format handling with magic number `SHADOW01` and version field
- **Wire Format**: `[Magic(8)][Version(2)][TLV Fields...]` with `[Type(1)][Length(4)][Value(Length)]` field structure
- **Test Coverage**: >90% coverage including edge cases, malformed data handling, and compatibility validation

### Summary
**Core Foundation Complete**: TLV header system ready for use in encryption workflows with extensible design supporting algorithm flexibility and metadata preservation. Clean architecture separation enables future enhancements without breaking existing functionality.

**Ready for Integration**: Header system can now be integrated into EncryptedFile domain entity and encryption/decryption workflows.

## [0.2.0] - 2025-10-04

### Added
- **Complete Architecture Rewrite**: Implemented clean layered architecture (domain/application/infrastructure/cli) aligned with domain specifications
- **Legacy Preservation**: Moved all existing code to `legacy/` folder preserving complete git history for reference during implementation
- **Domain Layer**: Created entities (EncryptedFile, PlaintextFile, CryptoSession, DuplicateDetector, FileMetadata), services (Encryption, Decryption, Listing, Migration), and repository interfaces
- **Application Layer**: Established workflows for end-to-end operations (EncryptionWorkflow, DecryptionWorkflow, ListingWorkflow, MigrationWorkflow)
- **Infrastructure Layer**: Prepared implementation slots for crypto, file system, and terminal operations
- **CLI Layer**: Restructured binary implementations (shadow, unshadow, shadows, shadowmigrate) with clean separation

### Changed
- **BREAKING CHANGE**: Complete codebase restructure - all previous module paths invalidated
- **Implementation Approach**: Legacy code preserved in `legacy/` for reference - new implementation follows `docs/specs/` precisely
- **Testing Strategy**: Removed legacy integration tests, established clean testing foundation for new architecture
- **Binary Paths**: Updated Cargo.toml to point to new CLI layer structure
- **Development Approach**: Shifted from incremental changes to clean slate implementation based on domain specifications

### Summary
This version completes the **architecture rewrite foundation phase**. All modules compile successfully with placeholder implementations ready for incremental feature development. Legacy implementations available in `legacy/src/` provide proven patterns for reference during clean reimplementation according to domain specifications.

**Foundation Ready**: Clean layered architecture with domain entities, services, workflows, and CLI structure
**Implementation Guide**: Use `docs/specs/DOMAIN_ARCHITECTURE.md` as blueprint, reference `legacy/src/` for proven patterns
**Next Phase**: Implement TLV Header System V1 as core cryptographic foundation

## [0.1.1] - 2025-10-04

### Added
- **Rewrite Implementation Plan**: Analyzed all specification documents and created comprehensive 20-task implementation roadmap
- **Architectural Insights**: Documented critical patterns to preserve (TLV headers, config providers, version matrix) and missing features to implement
- **Priority Classification**: Established P0-P3 priority framework for systematic implementation across 5 phases
- **Technical Requirements**: Identified stateless design principle, clean architecture layers, and security-first approach

### Discovered
- **Critical Missing Features**: Double password verification, duplicate content detection, --keep flag behavior, source removal defaults
- **Excellent Preserved Patterns**: TLV header extensibility, trait-based dependency injection, version compatibility matrix, error handling philosophy
- **Implementation Strategy**: Infrastructure → Cryptographic → Domain → CLI integration with breaking changes preferred over backward compatibility

### Changed
- **Development Approach**: Established comprehensive understanding of target architecture for efficient rewrite execution
- **Documentation Quality**: Enhanced with detailed technical analysis and implementation considerations

### Summary
This version completes the **specification analysis phase** and establishes the foundation for systematic rewrite implementation. All 20 implementation tasks identified with clear priorities and technical requirements. Ready to begin Phase 1: Core Infrastructure implementation.

**Next Phase**: Implement TLV Header System V1 and Configuration Provider Pattern
**Foundation**: Complete architectural understanding with preserved patterns and missing features identified

## [0.1.0] - 2025-10-04

### Added
- **Complete Rewrite Specifications**: Created comprehensive architectural specifications in `docs/specs/` for complete system rewrite
- **Architecture Documentation**: Established preserved patterns, missing features, domain architecture, and feature requirements
- **Clean Development Foundation**: Prepared codebase for complete architectural rebuild with minimal technical debt
- **Crates.io Publication**: Initial publication to claim package name for future development

### Changed
- **CHANGELOG Cleanup**: Drastically reduced changelog to essential project wisdom for rewrite preparation
- **Documentation Focus**: Shifted from legacy version tracking to forward-looking rewrite specifications

### Summary
This version marks the **preparation phase for a complete architectural rewrite**. All specifications are documented in `docs/specs/` directory. The current implementation provides foundation patterns and lessons learned that will inform the new architecture. No functional changes to the encryption system in this release.

**Next Phase**: Complete system rewrite based on established specifications
**Foundation**: TLV header system, trait-based configuration, security patterns preserved
