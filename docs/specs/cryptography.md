# Cryptography Specification

Detailed cryptographic protocols, algorithms, and implementation details for the high-security file encryption system.

## Core Cryptographic Primitives

### AES-256-GCM Authenticated Encryption

The system uses AES-256 in Galois/Counter Mode (GCM) as the primary authenticated encryption algorithm:

```rust
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Key};
use aes_gcm::aead::{Aead, AeadCore, OsRng};

// Key derivation from password
let key = derive_key(password, salt)?;
let cipher = Aes256Gcm::new(&key);

// Encryption with authentication
let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;
```

**Properties:**
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes) - optimal for GCM
- **Authentication Tag**: 128 bits (16 bytes)
- **Performance**: Hardware acceleration on modern CPUs
- **Security**: Provides both confidentiality and authenticity

### Argon2id Key Derivation

Password-based key derivation uses Argon2id with carefully tuned parameters:

```rust
use argon2::{Argon2, Algorithm, Version, Params, PasswordHasher};

const MEMORY_COST: u32 = 65536;      // 64 MiB memory usage
const TIME_COST: u32 = 3;            // 3 iterations
const PARALLELISM: u32 = 4;          // 4 parallel threads
const OUTPUT_LENGTH: usize = 32;     // 256-bit output

let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LENGTH))?;
let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

// Derive 256-bit key from password
let key = argon2.hash_password(password.as_bytes(), &salt)?;
```

**Parameter Justification:**
- **Memory Cost (64 MiB)**: Balances security with usability on modern systems
- **Time Cost (3 iterations)**: Provides ~200ms delay on modern hardware
- **Parallelism (4 threads)**: Optimizes for typical CPU core counts
- **Argon2id variant**: Resistant to both side-channel and time-memory trade-off attacks

### Secure Random Number Generation

All cryptographic randomness uses the operating system's cryptographically secure RNG:

```rust
use rand_core::{OsRng, RngCore};

// Generate cryptographic salt
let mut salt = [0u8; 16];
OsRng.fill_bytes(&mut salt);

// Generate GCM nonce
let mut nonce = [0u8; 12];
OsRng.fill_bytes(&mut nonce);
```

**Sources:**
- **macOS**: `/dev/random` via Security framework
- **Linux**: `getrandom()` system call
- **Windows**: `BCryptGenRandom` API

## Cryptographic Agility Architecture

### Algorithm Identifier System

The system supports multiple algorithms through a unified interface:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AlgorithmId {
    AesGcm256 = 0x0001,
    ChaCha20Poly1305 = 0x0002,
    
    // Post-quantum algorithms (reserved)
    KyberAes256 = 0x1001,
    DilithiumAes256 = 0x1003,
}

pub trait CryptoAlgorithm {
    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn key_size(&self) -> usize;
    fn nonce_size(&self) -> usize;
    fn tag_size(&self) -> usize;
}
```

### Future Algorithm Integration

The architecture is designed to support:

**ChaCha20-Poly1305:**
- Alternative to AES for systems without hardware acceleration
- 256-bit key, 96-bit nonce, 128-bit authentication tag
- Software-optimized performance

**Post-Quantum Cryptography:**
- CRYSTALS-Kyber for key encapsulation
- CRYSTALS-Dilithium for digital signatures
- Hybrid modes combining classical and post-quantum algorithms

## Key Management

### Key Derivation Hierarchy

```
User Password
     |
     v
[Argon2id] + Salt
     |
     v
Master Key (256 bits)
     |
     +-- Directory Encryption Key
     +-- Filename Encryption Key  
     +-- Metadata Encryption Key
     +-- Content Encryption Key
```

Each component is encrypted with a separate derived key to provide cryptographic isolation.

### Key Derivation Implementation

```rust
pub struct KeyDerivation {
    master_key: SecretVec<u8>,
}

impl KeyDerivation {
    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self> {
        let master_key = derive_master_key(password, salt)?;
        Ok(Self { master_key: SecretVec::new(master_key) })
    }
    
    pub fn derive_section_key(&self, section: SectionType) -> SecretVec<u8> {
        let info = match section {
            SectionType::Directory => b"directory_key_v1",
            SectionType::Filename => b"filename_key_v1", 
            SectionType::Metadata => b"metadata_key_v1",
            SectionType::Content => b"content_key_v1",
        };
        
        let key = hkdf_expand(&self.master_key, info, 32);
        SecretVec::new(key)
    }
}
```

## Secure Memory Management

### SecretVec Implementation

Sensitive data is protected using a custom secure memory type:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretVec<T: Zeroize + Clone> {
    data: Vec<T>,
}

impl<T: Zeroize + Clone> SecretVec<T> {
    pub fn new(data: Vec<T>) -> Self {
        Self { data }
    }
    
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

impl<T: Zeroize + Clone> Drop for SecretVec<T> {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
```

**Security Properties:**
- **Automatic zeroization**: Memory cleared on drop
- **No debug output**: Prevents accidental logging
- **Clone protection**: Ensures all copies are zeroized
- **Type safety**: Compile-time guarantees for sensitive data

### Memory Protection Features

- **Stack protection**: Sensitive data on stack is zeroized
- **Heap protection**: Heap allocations cleared before deallocation
- **Swap protection**: Advises OS to avoid paging sensitive memory
- **Core dump protection**: Prevents sensitive data in crash dumps

## Authentication and Integrity

### Per-Section Authentication

Each section of the encrypted file has independent authentication:

```rust
pub struct AuthenticatedSection {
    pub encrypted_data: Vec<u8>,
    pub auth_tag: [u8; 16],
}

impl AuthenticatedSection {
    pub fn encrypt(
        algorithm: &dyn CryptoAlgorithm,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
    ) -> Result<Self> {
        let ciphertext = algorithm.encrypt(key, nonce, plaintext)?;
        let (encrypted_data, auth_tag) = split_ciphertext_and_tag(&ciphertext);
        
        Ok(Self {
            encrypted_data,
            auth_tag: auth_tag.try_into()?,
        })
    }
    
    pub fn decrypt(
        &self,
        algorithm: &dyn CryptoAlgorithm,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ciphertext = self.encrypted_data.clone();
        ciphertext.extend_from_slice(&self.auth_tag);
        
        algorithm.decrypt(key, nonce, &ciphertext)
    }
}
```

### Integrity Verification Chain

1. **Header Structure**: Magic number and version validation
2. **Section Authentication**: GCM tag verification for each section
3. **Content Hash**: SHA-256 verification of decrypted content
4. **Metadata Consistency**: Cross-validation of file attributes

## Cryptographic Security Analysis

### Attack Resistance

**Confidentiality:**
- AES-256 provides 256-bit security against cryptanalytic attacks
- GCM mode prevents chosen-plaintext attacks
- Independent keys prevent cross-contamination

**Authenticity:**
- GCM authentication tags prevent tampering
- Per-section authentication enables partial verification
- Nonce uniqueness prevents replay attacks

**Availability:**
- Robust error handling prevents denial-of-service
- Multiple algorithm support ensures long-term viability
- Backward compatibility maintains access to older files

### Threat Model Coverage

**Passive Attacks:**
- Ciphertext-only analysis: Cryptographically infeasible
- Known-plaintext attacks: GCM mode provides resistance
- Statistical analysis: Uniform ciphertext distribution

**Active Attacks:**
- Tampering detection: Authentication tags prevent modification
- Replay attacks: Unique nonces per encryption
- Chosen-ciphertext attacks: GCM provides resistance

**Implementation Attacks:**
- Side-channel resistance: Hardware AES implementation
- Timing attacks: Constant-time operations where possible
- Memory attacks: Secure memory management

## Performance Characteristics

### Encryption Performance

**Throughput (typical modern CPU):**
- AES-256-GCM: ~2-4 GB/s with hardware acceleration
- ChaCha20-Poly1305: ~1-2 GB/s software implementation
- Argon2id: ~200ms for key derivation (tunable)

**Memory Usage:**
- Header parsing: <1 KB working memory
- Key derivation: 64 MB peak usage
- Streaming encryption: <16 KB buffer per operation

### Optimization Strategies

**Hardware Acceleration:**
- AES-NI instructions on x86/x64 processors
- ARM Cryptography Extensions on ARM64
- Automatic detection and fallback to software

**Parallel Processing:**
- Independent section encryption enables parallelization
- Argon2id utilizes multiple CPU cores
- Future support for SIMD operations

## Implementation Standards

### Constant-Time Operations

Critical operations use constant-time implementations:

```rust
use subtle::ConstantTimeEq;

// Constant-time password verification
fn verify_password(stored_hash: &[u8], provided_hash: &[u8]) -> bool {
    stored_hash.ct_eq(provided_hash).into()
}

// Constant-time array comparison
fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
```

### Error Handling

Cryptographic errors are handled without information leakage:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Invalid key size")]
    InvalidKeySize,
    
    #[error("Encryption failed")]
    EncryptionFailed,
    
    #[error("Decryption failed")]
    DecryptionFailed,
}
```

All errors use generic messages to prevent side-channel information leakage.

### Testing Framework

Comprehensive testing ensures cryptographic correctness:

- **Unit tests**: Individual algorithm correctness
- **Integration tests**: End-to-end encryption/decryption
- **Property tests**: Invariant verification across inputs
- **Performance tests**: Regression detection for optimizations
- **Security tests**: Known-answer tests from standards

See [security.md](security.md) for security analysis and [performance.md](performance.md) for detailed performance characteristics.