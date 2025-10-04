# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
