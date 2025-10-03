# Shadow File Encryption Suite - Feature Requirements Documentation

**Document Version**: 1.0  
**Date**: October 3, 2025  
**Status**: Complete Analysis of Current Implementation

## 📋 **EXECUTIVE SUMMARY**

The Shadow file encryption suite consists of 4 CLI binaries that provide comprehensive file encryption, decryption, management, and analysis capabilities. This document provides a complete analysis of all currently implemented features based on examination of the binary source code.
- **Default Source Removal**: Remove source files by default after successful operations
- **Source Preservation Option**: `--keep` flag to preserve source files when needed
- **Double Password Verification**: Require password confirmation during encryption
- **Double-Encryption Prevention**: Detect and prevent encrypting already encrypted files
- **Duplicate Content Prevention**: Prevent encrypting identical file contents multiple times
- **Integrity Verification**: Verify operation success before any source removalhensive file encryption, decryption, management, and analysis capabilities. This document provides a complete analysis of all currently implemented features based on examination of the binary source code.

### **Feature Implementation Status**
- ✅ **Fully Implemented**: `shadow`, `unshadow`, `shadows`, `shadowmigrate`

---

## 🔐 **1. SHADOW (shadow.rs) - File Encryption**

### **Purpose**
Primary encryption binary for converting plaintext files to encrypted `.shadow` files.

### **Core Features**

#### **File Processing**
- ✅ **Single File Encryption**: Individual file processing with detailed progress
- ✅ **Multi-File Batch Encryption**: Glob pattern expansion for batch operations
- ✅ **Glob Pattern Support**: `*.txt`, `documents/*.pdf`, `sensitive/*` patterns
- ✅ **Double-Encryption Prevention**: Detects already encrypted files automatically
- ✅ **Duplicate Content Detection**: Prevents encrypting the same file content multiple times
- ✅ **Content Hash Verification**: Detect duplicate content even with different filenames

#### **Algorithm Support**
- ✅ **XChaCha20-Poly1305**: Default algorithm (enhanced security)
- ✅ **AES-256-GCM**: Alternative algorithm (maximum compatibility)
- ✅ **Algorithm Selection**: `--algorithm xchacha20|aes-gcm` flag
- ✅ **Algorithm Display**: Shows selected algorithm during encryption

#### **Security Features**
- ✅ **Double Password Verification**: Prompt twice during encryption to prevent data loss from typos
- ✅ **Secure Password Prompting**: Hidden password input
- ✅ **Double-Encryption Prevention**: Detect and prevent encrypting already encrypted `.shadow` files
- ✅ **Duplicate Content Prevention**: Detect and prevent encrypting identical file contents
- ✅ **Content Fingerprinting**: Use content hashes to identify duplicate files regardless of filename
- ✅ **Filename Obfuscation**: `--obfuscate` flag generates random encrypted filenames
- ✅ **Original Filename Storage**: Encrypted in file header for restoration
- ✅ **File Overwrite Protection**: Prevents accidental overwrite without `--force`

#### **File Management**
- ✅ **Default Source Removal**: Remove source files by default after successful operation
- ✅ **Source Preservation**: `--keep` flag to preserve source files
- ✅ **Atomic Operations**: Ensure file integrity during all operations
- ✅ **Integrity Verification**: Verify operation success before source removal
- ✅ **Secure Deletion**: Overwrites source files securely before removal

#### **User Experience**
- ✅ **Progress Reporting**: Real-time progress indicators with timing
- ✅ **Quiet Mode**: `--quiet` flag for minimal output
- ✅ **Error Handling**: Comprehensive error messages with hints
- ✅ **File Extension**: Automatic `.shadow` extension addition

### **Command Line Interface**

```bash
shadow [OPTIONS] <input_files_or_patterns>...

OPTIONS:
  -a, --algorithm <ALG>     Encryption algorithm: xchacha20 (default), aes-gcm
  -o, --obfuscate           Obfuscate the original filename for privacy
  -f, --force               Overwrite existing output files without prompting
  -k, --keep                Keep source files after successful encryption (default: remove)
  -q, --quiet               Minimal output (no progress indicators)
  -h, --help                Show help message

EXAMPLES:
  shadow secret.txt                    # Encrypt and remove source
  shadow --keep secret.txt             # Encrypt and keep source
  shadow --algorithm xchacha20 secret.txt
  shadow file1.txt file2.txt file3.txt
  shadow *.txt
  shadow --obfuscate documents/*.pdf
  shadow --keep --obfuscate sensitive/*
```

### **Output Examples**
```
🔐 Encrypting file: secret.txt
📄 Output file: secret.txt.shadow
🎭 Filename obfuscation: DISABLED
🔑 Using password-based encryption with XChaCha20-Poly1305

🔍 Checking for duplicate content... ✓ (2ms)

Enter password for encryption: [hidden]
Confirm password: [hidden]

🔄 Encrypting file... ✓ (127ms)
✅ Encryption completed in 127ms
✅ File encrypted successfully!
🔒 Encrypted file: secret.txt.shadow
🗑️ Source file securely removed: secret.txt
```

**Duplicate Detection Example:**
```
🔐 Encrypting file: document_copy.txt
🔍 Checking for duplicate content... ⚠️ (3ms)
❌ Error: File content matches already encrypted file 'document.txt.shadow'
   Duplicate encryption prevented to avoid redundant encrypted files.
   Hint: Use different content or decrypt existing file first.
```

---

## 🔓 **2. UNSHADOW (unshadow.rs) - File Decryption**

### **Purpose**
Primary decryption binary for converting encrypted `.shadow` files back to plaintext.

### **Core Features**

#### **File Processing**
- ✅ **Single File Decryption**: Individual file processing with detailed progress
- ✅ **Multi-File Batch Decryption**: Glob pattern expansion for batch operations
- ✅ **Automatic Algorithm Detection**: Reads algorithm from file header
- ✅ **Version Compatibility**: Handles different Shadow file format versions

#### **Filename Restoration**
- ✅ **Automatic Filename Recovery**: Extracts original filename from header
- ✅ **Obfuscated Name Handling**: Restores original names from obfuscated files
- ✅ **Extension Removal**: Automatically removes `.shadow` extension

#### **Security Features**
- ✅ **Secure Password Prompting**: Hidden password input
- ✅ **Cryptographic Authentication**: Verifies file integrity during decryption
- ✅ **File Validation**: Checks file existence and readability before processing

#### **File Management**
- ✅ **Default Source Removal**: Remove source files by default after successful operation
- ✅ **Source Preservation**: `--keep` flag to preserve source files
- ✅ **Atomic Operations**: Ensure file integrity during all operations
- ✅ **Integrity Verification**: Verify decryption success before source removal
- ✅ **File Overwrite Protection**: Prevents accidental overwrite without `--force`

#### **User Experience**
- ✅ **Progress Reporting**: Real-time progress indicators with timing
- ✅ **Quiet Mode**: `--quiet` flag for minimal output
- ✅ **Error Handling**: User-friendly error messages for common issues

### **Command Line Interface**

```bash
unshadow [OPTIONS] <input_files_or_patterns>...

OPTIONS:
  -f, --force               Overwrite existing output files without prompting
  -k, --keep                Keep source files after successful decryption (default: remove)
  -q, --quiet               Minimal output (no progress indicators)
  -h, --help                Show help message

EXAMPLES:
  unshadow secret.txt.shadow           # Decrypt and remove encrypted file
  unshadow --keep secret.txt.shadow    # Decrypt and keep encrypted file
  unshadow file1.txt.shadow file2.txt.shadow
  unshadow *.shadow
```

### **Output Examples**
```
🔓 Decrypting file: secret.txt.shadow
📄 Output file: secret.txt
🔑 Using password-based decryption with XChaCha20-Poly1305

Enter password for decryption: [hidden]

🔄 Decrypting and verifying file... ✓ (89ms)
✅ Decryption completed in 89ms
📄 Decrypted file: secret.txt
🗑️ Source file securely removed: secret.txt.shadow
```

---

## 📋 **3. SHADOWS (shadows.rs) - File Listing**

### **Purpose**
Directory scanning and listing tool for encrypted files with original filename display.

### **Core Features**

#### **Directory Scanning**
- ✅ **Recursive File Discovery**: Finds all `.shadow` files in specified directory
- ✅ **Default Current Directory**: Scans current directory if none specified
- ✅ **Path Validation**: Validates directory existence and accessibility

#### **Filename Decryption**
- ✅ **Original Name Display**: Decrypts and shows original filenames
- ✅ **Obfuscated Name Mapping**: Shows `obfuscated_name → original_name` mapping
- ✅ **Password-Based Access**: Requires password to decrypt filename metadata

#### **File Information Display**
- ✅ **Status Indicators**: Success/failure of password verification (✓/✗)
- ✅ **Original Filename**: Decrypted original filename (when password works)
- ✅ **Obfuscated Filename**: Current encrypted filename on disk
- ✅ **File Version**: Shadow file format version (V1, V2, V3, etc.)
- ✅ **Algorithm Information**: Encryption algorithm used (AES-GCM, XChaCha20-Poly1305)
- ✅ **File Size**: File size in human-readable format
- ✅ **Modification Time**: Last modified timestamp
- ✅ **Smart Ordering**: Successful decryptions first (alphabetically), then failed attempts

#### **User Experience**
- ✅ **Progress Indicators**: Shows scanning and formatting progress
- ✅ **Performance Reporting**: Reports operation timing
- ✅ **Empty Directory Handling**: Graceful handling when no files found
- ✅ **Color-Coded Output**: Visual hierarchy for easy reading
- ✅ **Professional Formatting**: Clean table layout with proper alignment

### **Command Line Interface**

```bash
shadows [OPTIONS] [directory]

ARGUMENTS:
  [directory]    Directory to scan for encrypted files (default: current directory)

OPTIONS:
  -h, --help     Show help message

EXAMPLES:
  shadows                           # List files in current directory
  shadows ./encrypted_files         # List files in specific directory  
  shadows /path/to/encrypted_docs   # List files in absolute path
  shadows ~/backup/shadow_files     # List files in home directory
```

### **Output Examples**
```
🔍 Scanning directory for encrypted files... ✓ (12ms)
📋 Formatting file listing... ✓ (3ms)

📁 Encrypted Files in './encrypted_files':
┌────────┬─────────────────────────┬─────────────────────┬─────┬───────────┬────────┬────────────┐
│ Status │ Original Name           │ Obfuscated Name     │ Ver │ Algorithm │ Size   │ Modified   │
├────────┼─────────────────────────┼─────────────────────┼─────┼───────────┼────────┼────────────┤
│   ✓    │ financial_report.xlsx   │ a1b2c3d4.shadow     │ V3  │ XChaCha20 │ 890KB  │ 2025-10-02 │
│   ✓    │ secret_document.pdf     │ e5f6g7h8.shadow     │ V3  │ AES-GCM   │ 2.1MB  │ 2025-10-03 │
│   ✓    │ user_manual.docx        │ i9j0k1l2.shadow     │ V2  │ XChaCha20 │ 1.2MB  │ 2025-09-30 │
├────────┼─────────────────────────┼─────────────────────┼─────┼───────────┼────────┼────────────┤
│   ✗    │ [encrypted]             │ m3n4o5p6.shadow     │ V3  │ XChaCha20 │ 1.5MB  │ 2025-10-01 │
│   ✗    │ [encrypted]             │ q7r8s9t0.shadow     │ V3  │ AES-GCM   │ 3.2MB  │ 2025-09-28 │
└────────┴─────────────────────────┴─────────────────────┴─────┴───────────┴────────┴────────────┘

✅ Listed 5 files in 15ms (3 successful, 2 failed password verification)
```

---

## 🔄 **4. SHADOWMIGRATE (shadowmigrate.rs) - File Format Migration**

### **Purpose**
Migration tool for updating encrypted files with outdated header versions to the latest file format version.

### **Core Features**
- ✅ **Version Detection**: Identify files with outdated header versions
- ✅ **Migration Execution**: Update file headers to current format version
- ✅ **Batch Processing**: Migrate multiple files in a directory
- ✅ **Safety Validation**: Ensure migration safety before execution

### **Command Line Interface**

```bash
shadowmigrate [file_or_directory]

ARGUMENTS:
  [file_or_directory]    File or directory to migrate (default: current directory)

EXAMPLES:
  shadowmigrate                        # Migrate all files in current directory
  shadowmigrate secret.txt.shadow      # Migrate single file
  shadowmigrate encrypted_files/       # Migrate all files in directory
```

---

## 🏗️ **ARCHITECTURE REQUIREMENTS**

### **Common Features Across All Binaries**

#### **Security Requirements**
- ✅ **Secure Password Handling**: Hidden input, secure memory handling
- ✅ **Cryptographic Authentication**: File integrity verification
- ✅ **Algorithm Flexibility**: Support for multiple encryption algorithms
- ✅ **Version Compatibility**: Support for file format evolution

#### **User Experience Requirements**
- ✅ **Progress Reporting**: Real-time feedback for all operations with timing information
- ✅ **Performance Tracking**: Operation duration measurement and throughput calculation
- ✅ **Error Handling**: User-friendly error messages with actionable hints
- ✅ **Help Systems**: Comprehensive help with examples

#### **File Management Requirements**
- ✅ **Default Source Removal**: Remove source files by default after successful operations
- ✅ **Source Preservation Option**: `--keep` flag to preserve source files when needed
- ✅ **Double Password Verification**: Require password confirmation during encryption
- ✅ **Integrity Verification**: Verify operation success before any source removal
- ✅ **Glob Pattern Support**: Batch processing with pattern matching
- ✅ **Overwrite Protection**: Prevent accidental file loss
- ✅ **Atomic Operations**: Ensure file integrity during operations
- ✅ **Secure Deletion**: Proper cleanup of sensitive data

### **Domain Layer Requirements**

Based on this comprehensive feature analysis, the domain layer must support:

#### **Core Entities**
1. **EncryptedFile**: File header, content, metadata management
2. **Algorithm**: Pluggable algorithm system (AES-GCM, XChaCha20-Poly1305)
3. **Credentials**: Password and key material handling
4. **FileMetadata**: Original filename, timestamps, sizes

#### **Domain Services**
1. **EncryptionService**: Algorithm selection, file encryption
2. **DecryptionService**: Algorithm detection, file decryption
3. **MigrationService**: Version analysis, migration planning
4. **AlgorithmRegistry**: Algorithm discovery and capability management

#### **Repository Interfaces**
1. **FileRepository**: File I/O abstraction
2. **ConfigRepository**: Configuration management
3. **MetadataRepository**: File metadata persistence

#### **Version Support**
- Current focus on V3 format with XChaCha20-Poly1305
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