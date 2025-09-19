# File Format Specification

Detailed specification of the encrypted file format, header structure, and serialization.

## File Header Format

The encrypted file format uses a comprehensive header that stores all necessary metadata for decryption while protecting against information leakage.

### Header Structure

```
[Magic: 4 bytes = "ENC3"]
[Version: 2 bytes = 3]
[Algorithm ID: 2 bytes]                   // Crypto agility (0x0001 = AES-256-GCM)
[Salt: 16 bytes]
[Nonce: 12 bytes]                         // GCM nonce (96-bit recommended)
[Directory Path Length: 2 bytes]          // Padded to prevent length leakage
[Encrypted Directory Path: variable]      // Original directory structure
[Directory Path Auth Tag: 16 bytes]       // GCM authentication tag
[Filename Length: 2 bytes]                // Padded to fixed maximum size
[Encrypted Filename: variable length]
[Filename Auth Tag: 16 bytes]             // GCM authentication tag
[Metadata Length: 2 bytes]                // Padded to prevent length leakage
[Encrypted Metadata: variable]            // File permissions, timestamps
[Metadata Auth Tag: 16 bytes]             // GCM authentication tag
[Encrypted Content: variable length]
[Content Auth Tag: 16 bytes]              // GCM authentication tag
```

### Algorithm Identifiers

The algorithm ID field enables cryptographic agility for future upgrades:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AlgorithmId {
    AesGcm256 = 0x0001,
    ChaCha20Poly1305 = 0x0002,  // Future algorithm
    
    // Post-quantum cryptography (reserved range 0x1000-0x1FFF)
    KyberAes256 = 0x1001,       // Future: CRYSTALS-Kyber + AES-256-GCM
    KyberChaCha20 = 0x1002,     // Future: CRYSTALS-Kyber + ChaCha20-Poly1305
    DilithiumAes256 = 0x1003,   // Future: CRYSTALS-Dilithium + AES-256-GCM
    
    // Streaming algorithms (reserved range 0x2000-0x2FFF)
    AesGcmStreaming = 0x2001,   // Future: Chunked AES-GCM for large files
}
```

### Padding Constants

To prevent information leakage about original file structures:

```rust
const MAX_FILENAME_LENGTH: usize = 512;     // Pad all filenames to this size
const MAX_DIRECTORY_PATH_LENGTH: usize = 2048;  // Pad all paths to this size  
const MAX_METADATA_LENGTH: usize = 256;     // Pad all metadata to this size
```

## Serialization Format

### Binary Layout

The header is serialized in little-endian format:

1. **Fixed Fields** (first 38 bytes):
   - Magic: 4 bytes (ASCII "ENC3")
   - Version: 2 bytes (little-endian u16)
   - Algorithm ID: 2 bytes (little-endian u16)
   - Salt: 16 bytes (random)
   - Nonce: 12 bytes (random, 96-bit for GCM)

2. **Directory Path Section**:
   - Length: 2 bytes (padded length)
   - Encrypted Data: variable bytes (padded to prevent leakage)
   - Auth Tag: 16 bytes (GCM authentication tag)

3. **Filename Section**:
   - Length: 2 bytes (padded length)
   - Encrypted Data: variable bytes (padded to MAX_FILENAME_LENGTH)
   - Auth Tag: 16 bytes (GCM authentication tag)

4. **Metadata Section**:
   - Length: 2 bytes (padded length)
   - Encrypted Data: variable bytes (serialized metadata)
   - Auth Tag: 16 bytes (GCM authentication tag)

5. **Content Section**:
   - Encrypted Data: variable bytes (file content)
   - Auth Tag: 16 bytes (GCM authentication tag)

### Metadata Format

File metadata is serialized as a binary structure:

```rust
struct FileMetadata {
    permissions: u32,                                    // File permissions
    created: SystemTime,                                 // Creation timestamp
    modified: SystemTime,                                // Modification timestamp
    accessed: SystemTime,                                // Access timestamp
    file_hash: [u8; 32],                                // SHA-256 of original content
    compression: Option<CompressionType>,                // Optional compression
    created_by: String,                                  // Software version
    custom_attributes: HashMap<String, Vec<u8>>,         // Extensible attributes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionType {
    None = 0x00,
    Zstd = 0x01,        // Zstandard compression
    Lz4 = 0x02,         // LZ4 fast compression
    Brotli = 0x03,      // Brotli compression
}
```

## Security Properties

### Header Enhancements

- **Replaced CBC+HMAC with GCM**: Single-pass authenticated encryption eliminates padding oracle vulnerabilities
- **Added algorithm identifier**: Enables cryptographic agility for future upgrades
- **Upgraded magic to "ENC3"**: Distinguishes from previous insecure formats
- **Length padding**: All variable-length fields padded to prevent information leakage
- **GCM nonces**: 96-bit nonces provide optimal performance and security
- **Backward compatibility**: Version field allows detection of older formats

### Authentication

Each section of the header has its own GCM authentication tag:

- **Directory Path**: Authenticated to prevent tampering with path information
- **Filename**: Authenticated to ensure filename integrity
- **Metadata**: Authenticated to protect file attributes
- **Content**: Authenticated to ensure data integrity

### Privacy Protection

- **Filename obfuscation**: Original filenames are encrypted and stored in header
- **Length padding**: All variable fields are padded to prevent size-based attacks
- **Format uniformity**: All encrypted files have similar structure regardless of content

## Implementation Details

### Serialization Process

1. **Generate cryptographic material**: salt, nonce, keys
2. **Serialize metadata**: Convert file metadata to binary format
3. **Encrypt sections**: Encrypt directory path, filename, metadata separately
4. **Authenticate sections**: Generate GCM tags for each section
5. **Assemble header**: Combine all components with proper padding
6. **Encrypt content**: Encrypt file content with final GCM tag

### Deserialization Process

1. **Parse fixed fields**: Extract magic, version, algorithm, salt, nonce
2. **Validate header**: Check magic number and algorithm support
3. **Parse variable sections**: Extract encrypted directory path, filename, metadata
4. **Verify authentication**: Check all GCM tags before decryption
5. **Decrypt sections**: Decrypt and validate each section
6. **Restore metadata**: Apply original file attributes

### Error Handling

The header format includes comprehensive error detection:

- **Magic number validation**: Immediate format detection
- **Version checking**: Compatibility verification
- **Algorithm support**: Graceful handling of unsupported algorithms
- **Authentication failure**: Clear indication of tampering or corruption
- **Malformed headers**: Robust parsing with detailed error messages

## Version Evolution

### Current Version (3)

- Magic: "ENC3"
- Algorithm agility support
- GCM authenticated encryption
- Comprehensive metadata storage
- Privacy-preserving padding

### Future Versions

The format is designed for evolution:

- **Version 4**: May add compression metadata
- **Version 5**: Post-quantum algorithm support
- **Version 6**: Streaming mode with chunked authentication

Each version maintains backward compatibility through the version field and algorithm identifiers.

## Platform Considerations

### Endianness

All multi-byte integers are stored in little-endian format for consistency across platforms.

### Timestamp Format

Timestamps are stored as seconds since Unix epoch (January 1, 1970) followed by nanoseconds, both as 64-bit little-endian integers.

### Path Separators

Directory paths are normalized to use forward slashes (/) regardless of platform, with conversion during restoration.

### Unicode Support

All text fields (filenames, paths) use UTF-8 encoding with proper validation during serialization and deserialization.

See [cryptography.md](cryptography.md) for cryptographic details and [security.md](security.md) for security analysis.