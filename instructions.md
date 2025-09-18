# Instructions for Reviewing File Encryption Program Design

## Overview
You are tasked with reviewing the architectural design of a file encryption program written in Rust. The program encrypts single files or directories with reversible filename obfuscation (no manifest), prioritizing **extreme security** and **high performance**. The design uses the **Dependency Inversion Principle (DIP)** for modularity and testability. Your goal is to identify potential improvements in **security**, **performance**, and **maintainability**, while adhering to the specified requirements.

## Design Summary

### Requirements
- **Functionality**: Encrypt single files or directories (recursive), obfuscate filenames reversibly without a manifest.
- **Cryptography**: Use AES-256-CBC for encryption, HMAC-SHA256 for integrity/authenticity. Per-file salts for key derivation (Argon2).
- **Header**: Each encrypted file has a header with metadata for decryption and name recovery.
- **No Compression**: Explicitly excluded.
- **DIP**: High-level components depend on abstractions (Rust traits), not concrete implementations.

### File Header Format
```
[Magic: 4 bytes = "ENC2"]
[Version: 2 bytes = 2]
[Salt: 16 bytes]
[IV: 16 bytes]
[Filename Length: 2 bytes]
[Encrypted Filename: variable length]
[Filename HMAC: 32 bytes]
[Encrypted Content: variable length]
[Content HMAC: 32 bytes]
```
- **Magic**: Identifies encrypted files.
- **Version**: Supports format evolution.
- **Salt**: Random per-file for Argon2 key derivation.
- **IV**: Random 16-byte value for AES-256-CBC.
- **Filename Length**: uint16 for parsing encrypted filename.
- **Encrypted Filename**: Original filename encrypted with AES-256-CBC (derived IV, e.g., HMAC(path, key)).
- **Filename HMAC**: HMAC-SHA256 of encrypted filename.
- **Content HMAC**: HMAC-SHA256 over header (up to filename HMAC) + content.
- **Obfuscated Filename**: Disk filename is Base64(HMAC(name, hmac_key)) for file system compatibility.

### Components and DIP
1. **Key Management**
   - **Trait**: `KeyDeriver`
     - Method: `derive_key(password: &str, salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>` (returns 32-byte AES key, 32-byte HMAC key).
   - **Implementation**: `Argon2KeyDeriver` (Argon2id, e.g., `m=64MiB`, `t=3`, `p=4`).
   - **Notes**: Per-file salts; cache keys in-memory for performance.

2. **Encryption/Decryption**
   - **Trait**: `Encryptor`
     - Methods:
       - `encrypt(enc_key: &[u8], hmac_key: &[u8], plaintext: &mut dyn Read, output: &mut dyn Write, iv: &[u8]) -> Result<Vec<u8>, Error>` (returns content HMAC).
       - `decrypt(enc_key: &[u8], hmac_key: &[u8], ciphertext: &mut dyn Read, output: &mut dyn Write, iv: &[u8], hmac: &[u8]) -> Result<(), Error>`.
       - `encrypt_name(enc_key: &[u8], hmac_key: &[u8], name: &str, path: &Path) -> Result<(Vec<u8>, Vec<u8>), Error>` (returns ciphertext, HMAC).
       - `obfuscate_name(key: &[u8], name: &str, path: &Path) -> Result<String, Error>` (disk filename).
       - `deobfuscate_name(enc_key: &[u8], hmac_key: &[u8], obfuscated: &str, path: &Path, ciphertext: &[u8], hmac: &[u8]) -> Result<String, Error>`.
   - **Implementation**: `AesCbcHmacEncryptor` (uses `aes`, `hmac`, `sha2` crates).
   - **Notes**: AES-256-CBC with PKCS#7 padding; HMAC-SHA256 for integrity; derived IV for names.

3. **File System**
   - **Trait**: `FileSystem`
     - Methods:
       - `read_file(path: &Path) -> Result<Box<dyn Read>, Error>`.
       - `write_file(path: &Path, content: &mut dyn Read) -> Result<(), Error>`.
       - `traverse_directory(root: &Path, recursive: bool) -> Result<Vec<PathBuf>, Error>`.
       - `rename_path(old: &Path, new: &Path) -> Result<(), Error>`.
       - `write_encrypted_file(path: &Path, header: Header, content: &mut dyn Read) -> Result<(), Error>`.
       - `read_encrypted_file(path: &Path) -> Result<(Header, Box<dyn Read>), Error>`.
   - **Implementation**: `LocalFileSystem` (uses `std::fs`, `std::path`).
   - **Notes**: Streams I/O; canonicalizes paths; parses/serializes headers.

4. **Header Value Object**
   - Structure:
     ```
     struct Header {
         magic: [u8; 4],         // "ENC2"
         version: u16,           // 2
         salt: [u8; 16],         // Random per file
         iv: [u8; 16],           // For AES-256-CBC
         filename_length: u16,   // Length of encrypted filename
         encrypted_filename: Vec<u8>,
         filename_hmac: [u8; 32],
         content_hmac: [u8; 32],
     }
     ```
   - Methods: `serialize() -> Vec<u8>`, `deserialize(data: &[u8]) -> Result<Self, Error>`.

5. **Orchestrator**
   - **Structure**: `EncryptorApp<K: KeyDeriver, E: Encryptor, F: FileSystem>`
   - **Main Method**: `encrypt_path(input: &Path, password: &str, recursive: bool) -> Result<(), Error>`
   - **Flow**:
     1. Traverse paths (`F::traverse_directory` or single file).
     2. For each file:
        - Generate random salt/IV (`OsRng`).
        - Derive keys (`K::derive_key`).
        - Obfuscate filename (`E::obfuscate_name`).
        - Encrypt filename (`E::encrypt_name`).
        - Encrypt content stream (`E::encrypt`).
        - Build `Header`.
        - Write header + content (`F::write_encrypted_file`).
        - Remove original if in-place.
     3. Decryption: Reverse (read header, verify HMACs, decrypt content/name, rename).

### Security and Performance Goals
- **Security**:
  - Use AES-256-CBC + HMAC-SHA256 for robust confidentiality/integrity.
  - Per-file salts for unique keys.
  - Secure RNG for salts/IVs.
  - Zeroize sensitive data (e.g., via `zeroize` crate).
  - Mitigate padding oracle attacks (HMAC covers ciphertext).
  - Prevent path traversal; constant-time HMAC verification.
- **Performance**:
  - Stream I/O for large files.
  - Parallelize file processing for directories (`rayon`).
  - Use hardware-accelerated AES (AES-NI).
  - Cache keys in-memory per session.
  - Minimize header overhead (~70-120 bytes).

## Review Tasks
1. **Security Analysis**:
   - Evaluate AES-256-CBC + HMAC-SHA256 for vulnerabilities (e.g., padding issues, IV management).
   - Assess per-file salts: Are there scenarios where session-wide salts are more secure or efficient?
   - Review filename obfuscation: Does Base64(HMAC) risk collisions or length issues? Suggest alternatives (e.g., truncated hash with counter).
   - Check header integrity: Is HMAC coverage sufficient? Any fields excluded incorrectly?
   - Identify side-channel risks (e.g., timing attacks in HMAC or key derivation).
   - Suggest additional mitigations (e.g., constant-time ops, memory wiping).

2. **Performance Optimization**:
   - Analyze header size impact (~70-120 bytes): Can it be reduced without compromising security?
   - Evaluate streaming I/O: Are there better buffering strategies (e.g., optimal buffer sizes)?
   - Assess parallelism: Are there risks in concurrent file processing (e.g., key access, disk contention)?
   - Recommend profiling techniques (e.g., `criterion`) for Rust implementation.
   - Suggest batching strategies for small files in directories.

3. **Maintainability and Extensibility**:
   - Review DIP usage: Are traits well-defined? Any missing abstractions (e.g., for header parsing)?
   - Assess header versioning: Does 2-byte version support future changes (e.g., new ciphers)?
   - Evaluate modularity: Can components (e.g., `Encryptor`) be reused in other contexts?
   - Suggest improvements for error handling (e.g., custom `Error` enum structure).
   - Propose testing strategies (e.g., mock `FileSystem` for unit tests).

4. **Edge Cases**:
   - Identify risks in filename handling (e.g., long names, special characters, collisions).
   - Check large file support (e.g., >4GB) with streaming.
   - Evaluate directory recursion limits (e.g., stack overflow, file system restrictions).
   - Suggest handling for interrupted operations (e.g., partial writes).

## Deliverables
- A report (markdown or text) summarizing findings, including:
  - Specific security vulnerabilities and mitigations.
  - Performance bottlenecks and optimization suggestions.
  - Maintainability improvements (e.g., refactoring, documentation).
  - Edge case handling recommendations.
- Optional: Updated header format or trait definitions if significant issues are found.
- Avoid implementing code unless explicitly requested; focus on design-level feedback.

## Constraints
- Must use AES-256-CBC + HMAC-SHA256 (no AES-GCM).
- Per-file salts are required.
- No manifest for filename mappings.
- No compression.
- Rust is the target language, but focus on design, not code.

## Additional Notes
- Use audited crates (`aes`, `hmac`, `sha2`, `argon2`, `rand`, `zeroize`) for implementations.
- Assume local file system (`std::fs`) for `FileSystem`.
- Prioritize **extreme security** (e.g., audited crypto, zeroization) and **high performance** (e.g., streaming, AES-NI).
- Consider threat models: offline attacks, tampering, side-channels.
- Refer to prior artifact (`file_header.md`, ID: 402d7976-578a-4b89-b3f8-6a4357f6c4ab) for header details.