# Shadow File Encryption Tool - Technical Specification

**Document Version**: 1.0  
**Date**: October 15, 2025  
**Status**: Draft  
**Target Implementation**: Simplified Shadow v1.0

---

## 1. Executive Summary

This specification defines the technical requirements for Shadow, a command-line file encryption utility that provides secure, authenticated encryption of individual files and file collections. The tool is designed following the Unix philosophy of doing one thing well, focusing exclusively on file encryption with optional filename obfuscation.

## 2. Design Principles

### 2.1 Core Principles
- **Single Responsibility**: Encryption only (decryption handled by separate `unshadow` utility)
- **Cryptographic Simplicity**: Single algorithm to reduce implementation complexity
- **User Choice**: Optional filename obfuscation based on user requirements
- **Batch Operations**: Support for multiple file processing with consistent behavior
- **Security First**: Implementation prioritizes correctness over performance

### 2.2 Security Objectives
- **Confidentiality**: File contents protected by authenticated encryption
- **Integrity**: File tampering detection through authentication tags
- **Authenticity**: Password-based authentication prevents unauthorized decryption
- **Privacy**: Optional filename obfuscation for metadata protection

## 3. Functional Requirements

### 3.1 Command Line Interface

#### 3.1.1 Basic Syntax
```
shadow [OPTIONS] <input_files>...
```

#### 3.1.2 Input File Specification
- **Single files**: Direct file path specification
- **Multiple files**: Space-separated file paths
- **Glob patterns**: Shell expansion patterns (*.txt, documents/*.pdf)
- **Path types**: Relative and absolute paths supported

#### 3.1.3 Command Line Options

| Option | Long Form | Description | Default |
|--------|-----------|-------------|---------|
| `-o` | `--obfuscate` | Generate random output filenames | Disabled |
| `-f` | `--force` | Overwrite existing output files | Disabled |
| `-k` | `--keep` | Preserve source files after encryption | Disabled |
| `-q` | `--quiet` | Suppress progress output | Disabled |
| `-h` | `--help` | Display usage information | N/A |

#### 3.1.4 Output Behavior

**Default Mode** (filename preservation):
- Input: `document.txt`
- Output: `document.txt.shadow`

**Obfuscation Mode** (`--obfuscate`):
- Input: `document.txt`
- Output: `a1b2c3d4-e5f6-7890-abcd-ef1234567890.shadow`

### 3.2 File Processing Workflow

#### 3.2.1 Input Validation
1. Verify file existence and readability
2. Check for existing output files (unless `--force` specified)
3. Validate available disk space for output files
4. Detect and prevent encryption of already encrypted files
5. **Content-based duplicate detection**: Prevent re-encryption of identical file contents

#### 3.2.2 Encryption Pipeline
1. **Password Collection**: Secure password prompt with confirmation
2. **Key Derivation**: Argon2id-based key derivation from password
3. **File Processing**: Individual file encryption with progress reporting
4. **Output Generation**: Atomic file creation with appropriate naming
5. **Source Management**: Optional source file removal based on `--keep` flag

#### 3.2.3 Error Handling
- **Input errors**: Clear messages for missing or inaccessible files
- **Cryptographic errors**: Secure error reporting without sensitive data exposure
- **System errors**: Appropriate handling of disk space, permissions, and I/O issues
- **Partial failures**: Continue processing remaining files on individual failures

## 4. Technical Specifications

### 4.1 Cryptographic Implementation

#### 4.1.1 Encryption Algorithm
- **Primary Cipher**: XChaCha20-Poly1305
- **Mode**: Authenticated Encryption with Associated Data (AEAD)
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 192 bits (24 bytes) for XChaCha20

#### 4.1.2 Key Derivation
- **Algorithm**: Argon2id
- **Production Parameters**:
  - Memory Cost: 1 GiB (1,048,576 KiB)
  - Time Cost: 5 iterations
  - Parallelism: 4 threads
- **Test Parameters** (for development/testing only):
  - Memory Cost: 64 KiB
  - Time Cost: 1 iteration
  - Parallelism: 1 thread
- **Salt Size**: 128 bits (16 bytes), randomly generated per file
- **Parameter Selection**: Test parameters enabled via compile-time feature flag or environment variable

#### 4.1.3 Nonce Generation
- **Source**: Cryptographically secure random number generator
- **Uniqueness**: New nonce generated for each encryption operation
- **Storage**: Prepended to ciphertext in file header

### 4.2 File Format Specification

#### 4.2.1 File Structure
```
[Header][Encrypted Payload]
```

#### 4.2.2 Header Format

**Unified Header Format** (both obfuscated and non-obfuscated):
```
┌─────────────────┬──────────────────┬─────────────────────┐
│ Magic (8 bytes) │ Metadata (var)   │ Crypto Data (var)   │
└─────────────────┴──────────────────┴─────────────────────┘

Magic: "SHADOW01" (ASCII)
Metadata:
  - Algorithm ID (1 byte): 0x01 (XChaCha20-Poly1305)
  - Obfuscation Flag (1 byte): 0x00 (disabled) or 0x01 (enabled)
  - Content Hash (32 bytes): SHA-256 of original file content
  - Filename Length (2 bytes, big-endian)
  - Original Filename (variable, UTF-8 or encrypted if obfuscated)
  - [If obfuscated] Filename Nonce (24 bytes)
Crypto Data:
  - Salt (16 bytes)
  - Content Nonce (24 bytes)
```

**Header Behavior**:
- **Without obfuscation**: Original filename stored in plaintext UTF-8
- **With obfuscation**: Original filename encrypted with separate nonce
- **Content hash**: Always included for duplicate detection
- **Filename nonce**: Only present when obfuscation flag is 0x01

#### 4.2.3 Encrypted Payload
- **Content**: Original file data encrypted with XChaCha20-Poly1305
- **Authentication**: Poly1305 authentication tag appended to ciphertext
- **Associated Data**: File header used as AAD for authentication

### 4.3 Duplicate Detection and Filename Obfuscation

#### 4.3.1 Content-Based Duplicate Detection
- **Content Hashing**: SHA-256 hash calculated for each input file before encryption
- **Header Storage**: Content hash stored in every file header for duplicate detection
- **Detection Process**: Scan existing `.shadow` files in target directory, reading headers to compare content hashes
- **Performance**: Only header reading required, no full file content processing

#### 4.3.2 Duplicate Detection Workflow
1. **Calculate content hash**: SHA-256 of input file content
2. **Scan target directory**: Read headers of all existing `.shadow` files
3. **Compare hashes**: Check if content hash already exists
4. **Report conflicts**: If duplicate found, display original filename and encrypted file location
5. **Force override**: `--force` flag bypasses duplicate detection

#### 4.3.3 Obfuscated Filename Generation
- **Format**: UUID4-based random filename with `.shadow` extension
- **Pattern**: `[8hex]-[4hex]-[4hex]-[4hex]-[12hex].shadow`
- **Example**: `a1b2c3d4-e5f6-7890-abcd-ef1234567890.shadow`

#### 4.3.4 Original Filename Protection
- **Encryption**: Original filename encrypted using separate key derivation when obfuscation enabled
- **Key Source**: HKDF-derived key from master key with label "filename"
- **Nonce**: Separate 24-byte nonce for filename encryption
- **Storage**: Encrypted filename stored in file header

#### 4.3.5 Duplicate Detection Error Messages
```bash
# For obfuscated files
$ shadow --obfuscate document.txt
Error: File 'document.txt' already encrypted
  Existing file: a1b2c3d4-e5f6-7890-abcd-ef1234567890.shadow
  Content hash: sha256:a1b2c3d4ef56...
  Use --force to encrypt anyway

# For non-obfuscated files
$ shadow document.txt  
Error: File 'document.txt' already encrypted as 'document.txt.shadow'
  Content hash: sha256:a1b2c3d4ef56...
  Use --force to overwrite existing file
```

## 5. Security Considerations

### 5.1 Threat Model
- **Adversary Capabilities**: File system access, passive observation
- **Protected Assets**: File contents, original filenames (when obfuscated)
- **Attack Vectors**: Cryptanalysis, password attacks, metadata analysis
- **Out of Scope**: Memory-based attacks, side-channel analysis, quantum attacks

### 5.2 Security Properties
- **Semantic Security**: Ciphertexts reveal no information about plaintexts
- **Authentication**: Tampering with encrypted files is detectable
- **Password Security**: Resistant to offline dictionary attacks
- **Metadata Protection**: Optional filename confidentiality

### 5.3 Implementation Security
- **Memory Management**: Sensitive data cleared from memory after use
- **Error Handling**: No sensitive information disclosed in error messages
- **Constant-Time Operations**: Password verification and authentication tag comparison
- **Secure Defaults**: Conservative cryptographic parameters

## 6. Performance Requirements

### 6.1 Processing Performance
- **Throughput**: Minimum 50 MB/s on commodity hardware
- **Memory Usage**: Maximum 2 GiB total memory footprint
- **Disk I/O**: Streaming processing for files larger than available memory

### 6.2 User Experience
- **Startup Time**: Maximum 100ms for command initialization
- **Progress Reporting**: Real-time progress for files larger than 10 MB
- **Responsiveness**: Progress updates every 100ms during processing

## 7. Compatibility Requirements

### 7.1 Platform Support
- **Primary Platforms**: Linux, macOS, Windows
- **Architecture**: x86_64, ARM64
- **Minimum Requirements**: 4 GB RAM, 1 GHz processor

### 7.2 File System Compatibility
- **Path Lengths**: Support for platform-maximum path lengths
- **Unicode Support**: Full UTF-8 filename support
- **Special Characters**: Proper handling of platform-specific filename restrictions

## 8. Quality Assurance

### 8.1 Testing Requirements
- **Unit Tests**: 100% coverage of cryptographic functions
- **Integration Tests**: End-to-end encryption workflow validation
- **Security Tests**: Negative testing for malformed inputs and error conditions
- **Performance Tests**: Benchmark testing on reference hardware

### 8.2 Security Validation
- **Cryptographic Review**: External audit of cryptographic implementation
- **Penetration Testing**: Black-box security assessment
- **Static Analysis**: Automated code security scanning
- **Dependency Audit**: Third-party library security assessment

## 9. Implementation Guidelines

### 9.1 Code Organization
- **Modular Design**: Separate modules for CLI, cryptography, and file operations
- **Error Propagation**: Consistent error handling with user-friendly messages
- **Dependency Management**: Minimal external dependencies, security-focused selection

### 9.2 Development Standards
- **Code Quality**: Comprehensive documentation and type safety
- **Security Practices**: Security-first development methodology
- **Version Control**: Signed commits and release tags
- **Build Reproducibility**: Deterministic build processes
- **Test Configuration**: Fast key derivation parameters for development testing (never in production builds)

## 10. Future Considerations

### 10.1 Extensibility
- **Header Versioning**: Support for future format extensions
- **Algorithm Agility**: Framework for additional encryption algorithms
- **Feature Flags**: Capability negotiation for optional features

### 10.2 Interoperability
- **Cross-Platform**: Consistent behavior across supported platforms
- **Forward Compatibility**: Future versions can decrypt current format
- **Standard Compliance**: Alignment with relevant cryptographic standards

---

**Document Control**:
- **Author**: Shadow Development Team
- **Review**: Pending
- **Approval**: Pending
- **Next Review**: Post-implementation security audit