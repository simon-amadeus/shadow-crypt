
# Shadow Rewrite Architecture Requirements

This document specifies the comprehensive architecture requirements for the Shadow file encryption suite rewrite, building on proven patterns from the current implementation while addressing missing features and improving overall design.

## 🏗️ **ARCHITECTURE OVERVIEW**

### **Layered Architecture**
```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Layer (Binaries)                     │ 
│    shadow | unshadow | shadows | shadowmigrate              │
├─────────────────────────────────────────────────────────────┤
│                Application Services Layer                    │
│     Workflows, Orchestration, Cross-cutting Concerns        │
├─────────────────────────────────────────────────────────────┤
│                     Domain Layer (Core)                     │
│   Entities, Services, Repository Interfaces, Business Logic │
├─────────────────────────────────────────────────────────────┤
│                 Infrastructure Layer (I/O)                  │
│   File System, Crypto Implementations, External Services    │
└─────────────────────────────────────────────────────────────┘
```

### **Core Design Principles**
1. **Preserve Excellent Patterns**: Maintain V3 TLV header, configuration providers, version compatibility
2. **Clean Architecture**: Domain-driven design with dependency inversion
3. **Security First**: All operations prioritize cryptographic security
4. **User Experience**: Consistent, helpful, and intuitive interfaces
5. **Future-Proof**: Extensible design supporting algorithm and version evolution

## 🔧 **PRESERVED ARCHITECTURAL PATTERNS**

### **V3 TLV Header System** ⭐⭐⭐
**Status**: Preserve exactly as-is
- **Extensible**: TLV fields allow new metadata without breaking compatibility
- **Algorithm-Agnostic**: Variable nonce lengths support any crypto algorithm  
- **Future-Proof**: Unknown fields preserved during roundtrip operations
- **Deterministic**: Consistent serialization ensures reproducible headers

### **Configuration Provider Pattern** ⭐⭐⭐
**Status**: Preserve with enhancements
- **Clean Dependency Injection**: Functions accept providers, not concrete types
- **Test/Production Separation**: Built-in fast vs secure configuration variants
- **Algorithm Decoupling**: Business logic independent of crypto implementations
- **Composable Design**: Separate key derivation and encryption concerns

### **Version Compatibility Matrix** ⭐⭐⭐
**Status**: Preserve and extend
- **Migration Planning**: Clear upgrade paths between versions
- **Capability Matrix**: Know what each version can/cannot do
- **Safety First**: Explicit compatibility checking prevents data corruption
- **Extensible**: Easy to add new versions without breaking existing logic

### **Error Handling Philosophy** ⭐⭐⭐
**Status**: Preserve approach, refine implementation
- **User-Friendly**: Non-technical explanations with actionable hints
- **Security-Conscious**: No sensitive implementation details leaked
- **Context Preservation**: Maintains error chain for debugging
- **Actionable Guidance**: Tells users what to do, not just what failed

## 🏗️ **CORE REQUIREMENTS**

### **Security Requirements**
- ✅ **Secure Password Handling**: Hidden input, secure memory management with automatic zeroization
- ✅ **Double Password Verification**: Require password confirmation during encryption operations
- ✅ **Cryptographic Authentication**: File integrity verification using authenticated encryption
- ✅ **Algorithm Flexibility**: Support multiple encryption algorithms via pluggable interface
- ✅ **Version Compatibility**: Support file format evolution with migration capabilities
- ✅ **Double-Encryption Prevention**: Detect and prevent encrypting already encrypted files
- ✅ **Content Fingerprinting**: SHA-256 content hashing for duplicate detection and integrity

### **User Experience Requirements**
- ✅ **Progress Reporting**: Real-time feedback for all operations with precise timing information
- ✅ **Performance Tracking**: Operation duration measurement and throughput calculation
- ✅ **Error Handling**: User-friendly error messages with actionable hints and suggestions
- ✅ **Help Systems**: Comprehensive help with practical examples and use cases
- ✅ **Consistent CLI**: Uniform flag behavior and argument patterns across all binaries
- ✅ **Batch Processing**: Efficient handling of multiple files with glob pattern expansion

### **File Management Requirements**
- ✅ **Default Source Removal**: Remove source files by default after successful operations
- ✅ **Source Preservation Option**: `--keep` flag to preserve source files when needed
- ✅ **Duplicate Content Prevention**: Detect and prevent encrypting identical file contents
- ✅ **Integrity Verification**: Verify operation success before any destructive actions
- ✅ **Glob Pattern Support**: Batch processing with robust pattern matching
- ✅ **Overwrite Protection**: Prevent accidental file loss without explicit `--force` flag
- ✅ **Atomic Operations**: Ensure file integrity during all operations using temporary files
- ✅ **Secure Deletion**: Cryptographically secure cleanup of sensitive data
- ✅ **Filename Obfuscation**: Optional random filename generation for privacy

## 🎯 **DOMAIN LAYER ARCHITECTURE**

### **Core Entities**
1. **EncryptedFile**: Complete encrypted file representation with header, content, and metadata
2. **PlaintextFile**: Source file representation with content hashing and metadata extraction  
3. **CryptoSession**: Manages cryptographic state, key material, and algorithm operations
4. **DuplicateDetector**: Handles content fingerprinting and duplicate file detection
5. **FileMetadata**: Original filename, timestamps, sizes, and other file attributes

### **Domain Services**
1. **EncryptionService**: Orchestrates file encryption with duplicate detection and progress reporting
2. **DecryptionService**: Manages file decryption with automatic filename restoration
3. **ListingService**: Directory scanning and encrypted file information extraction
4. **MigrationService**: Version analysis, migration planning, and execution
5. **AlgorithmRegistry**: Algorithm discovery, capability management, and selection

### **Repository Interfaces**
1. **FileRepository**: File I/O abstraction with atomic operations and secure deletion
2. **ConfigRepository**: Configuration management and user preferences storage
3. **PasswordRepository**: Password input handling with confirmation and strength validation
4. **MetadataRepository**: File metadata persistence and retrieval

## 🚀 **APPLICATION SERVICES LAYER**

### **Workflow Orchestration**
1. **EncryptionWorkflow**: End-to-end encryption process with all validations and features
2. **DecryptionWorkflow**: Complete decryption process with filename restoration
3. **ListingWorkflow**: Directory scanning and information display coordination
4. **MigrationWorkflow**: Version upgrade planning and execution management

### **Cross-Cutting Concerns**
1. **Progress Reporting**: Consistent progress feedback across all operations
2. **Error Handling**: Centralized error processing with user-friendly messages
3. **Logging**: Structured logging for debugging and audit trails
4. **Performance Monitoring**: Operation timing and throughput measurement

## 📊 **ALGORITHM AND VERSION SUPPORT**

### **Current Algorithm Support**
- **XChaCha20-Poly1305**: Default algorithm for enhanced security with extended nonces
- **AES-256-GCM**: Alternative algorithm for maximum compatibility
- **Pluggable Interface**: New algorithms can be added without core changes

### **Version Management**
- **V3 Format**: Current implementation with TLV extensible headers
- **Migration Path**: Clear upgrade routes from V1/V2 to V3 and future versions
- **Compatibility Matrix**: Explicit support for reading/writing different versions
- **Future-Proof**: Extensible design supports new versions and features

## 🔒 **SECURITY ARCHITECTURE**

### **Cryptographic Design**
- **Authenticated Encryption**: All algorithms must provide authentication (AEAD)
- **Key Derivation**: Argon2id with adaptive parameters for password-based keys
- **Secure Random**: All nonces, salts, and keys from cryptographically secure sources
- **Memory Protection**: Automatic zeroization of sensitive data using secure containers

### **Attack Surface Minimization**
- **Input Validation**: Comprehensive validation of all file inputs and user data
- **Error Information**: No sensitive details leaked through error messages
- **Side-Channel Resistance**: Constant-time operations where applicable
- **Dependency Security**: Minimal external dependencies with security audit trails

## 🎛️ **CONFIGURATION MANAGEMENT**

### **Algorithm Configuration**
```rust
pub trait CryptoConfig: KeyDerivationConfig + EncryptionConfig {
    fn test_config() -> Self;      // Fast parameters for testing
    fn production_config() -> Self; // Secure parameters for production
}
```

### **User Preferences**
- **Default Algorithm**: User-configurable default encryption algorithm
- **Search Paths**: Configurable directories for duplicate detection
- **Behavior Settings**: Default source removal, progress reporting preferences
- **Security Settings**: Password strength requirements, confirmation policies

## 🧪 **TESTING STRATEGY**

### **Testing Pyramid**
1. **Unit Tests**: Domain entities, services, and business logic
2. **Integration Tests**: Application services and workflow orchestration  
3. **End-to-End Tests**: Complete CLI operations with real filesystem
4. **Property-Based Tests**: Cryptographic roundtrips and data integrity

### **Test Infrastructure**
- **Mock Repositories**: In-memory implementations for fast unit testing
- **Test Configurations**: Fast crypto parameters for test performance
- **Fixture Management**: Consistent test data and encrypted file samples
- **Performance Benchmarks**: Regression testing for encryption/decryption speed

## 📈 **PERFORMANCE REQUIREMENTS**

### **Scalability Targets**
- **Large Files**: Efficient handling of files up to several gigabytes
- **Batch Operations**: Process hundreds of files with minimal overhead
- **Memory Usage**: Constant memory usage independent of file size
- **Progress Feedback**: Sub-second responsiveness for user interface updates

### **Optimization Strategies**
- **Streaming Operations**: Process files without loading entirely into memory
- **Parallel Processing**: Concurrent file operations where safe and beneficial
- **Hardware Acceleration**: Leverage AES-NI and other crypto accelerations
- **Efficient Algorithms**: Choose algorithms with good performance characteristics

## 🔄 **EXTENSIBILITY DESIGN**

### **Algorithm Extensibility**
- **Plugin Architecture**: New algorithms via trait implementations
- **Configuration Integration**: Automatic configuration provider support
- **Version Compatibility**: Algorithm additions don't break existing files
- **Performance Isolation**: Algorithm-specific optimizations don't affect core logic

### **Feature Extensibility**  
- **TLV Header Fields**: New metadata types via TLV field additions
- **CLI Extensions**: New command-line options without breaking changes
- **Repository Implementations**: Alternative storage backends (cloud, database)
- **Workflow Customization**: Pluggable workflow steps and validations

This architecture provides a solid foundation for the Shadow rewrite while preserving the excellent patterns from the current implementation and addressing all missing features with clean, maintainable, and secure code.
- Extensible design for future version support
- Migration path planning and execution

---

## 🎯 **DOMAIN DESIGN IMPLICATIONS**

This feature analysis reveals several critical domain layer requirements:

1. **Algorithm Authority Resolution**: 
   - Encryption: User configuration determines algorithm choice
   - Decryption: File header determines algorithm (what was used)
   - Migration: Version compatibility determines available algorithms

2. **Configuration Injection Points**:
   - CLI argument parsing → algorithm selection
   - Password prompting → credential creation  
   - File header reading → algorithm detection
   - Performance parameters → optimization settings

3. **Extensibility Requirements**:
   - New algorithms must integrate seamlessly
   - New file versions must maintain backward compatibility
   - New use cases must compose existing domain services

4. **Cross-Cutting Concerns**:
   - Progress reporting for long operations
   - Error handling with user-friendly messages
   - Secure memory handling throughout
   - Performance monitoring and optimization
   - Double-encryption and duplicate content prevention
   - Content fingerprinting for duplicate detection

This comprehensive feature analysis provides the foundation for designing a clean domain layer that supports all current functionality while maintaining security, performance, extensibility, and data integrity requirements.