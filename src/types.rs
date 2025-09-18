use serde::{Deserialize, Serialize};
use secrecy::Secret;
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

/// Secure container for cryptographic key material
#[derive(Clone)]
pub struct KeyMaterial {
    pub encryption_key: Secret<[u8; 32]>,
    pub hmac_key: Secret<[u8; 32]>,
    pub obfuscation_key: Secret<[u8; 32]>,
}

impl KeyMaterial {
    pub fn new(encryption_key: [u8; 32], hmac_key: [u8; 32], obfuscation_key: [u8; 32]) -> Self {
        Self {
            encryption_key: Secret::new(encryption_key),
            hmac_key: Secret::new(hmac_key),
            obfuscation_key: Secret::new(obfuscation_key),
        }
    }
}

/// Session key with caching information
#[derive(Clone)]
pub struct SessionKey {
    pub key_material: KeyMaterial,
    pub salt: [u8; 16],
    pub cache_until: Instant,
}

/// File header format as specified in the design
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u16,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    pub directory_path_length: u16,
    pub encrypted_directory_path: Vec<u8>,
    pub directory_path_hmac: [u8; 32],
    pub filename_length: u16,
    pub encrypted_filename: Vec<u8>,
    pub filename_hmac: [u8; 32],
    pub metadata_length: u16,
    pub encrypted_metadata: Vec<u8>,
    pub metadata_hmac: [u8; 32],
}

impl Header {
    pub const MAGIC: [u8; 4] = *b"ENC2";
    pub const VERSION: u16 = 2;
    
    pub fn new() -> Self {
        Self {
            magic: Self::MAGIC,
            version: Self::VERSION,
            salt: [0; 16],
            iv: [0; 16],
            directory_path_length: 0,
            encrypted_directory_path: Vec::new(),
            directory_path_hmac: [0; 32],
            filename_length: 0,
            encrypted_filename: Vec::new(),
            filename_hmac: [0; 32],
            metadata_length: 0,
            encrypted_metadata: Vec::new(),
            metadata_hmac: [0; 32],
        }
    }
    
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.version == Self::VERSION
    }
}

impl Default for Header {
    fn default() -> Self {
        Self::new()
    }
}

/// File metadata for preservation during encryption/decryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub permissions: u32,
    pub created: SystemTime,
    pub modified: SystemTime,
    pub accessed: SystemTime,
}

/// Information about an encrypted file for listing purposes
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub original_name: String,
    pub obfuscated_name: String,
    pub original_path: PathBuf,
    pub size: u64,
    pub encrypted_size: u64,
    pub modified: SystemTime,
}

/// Transaction identifier for recovery operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionId(pub u64);

impl TransactionId {
    pub fn new() -> Self {
        use rand::Rng;
        Self(rand::thread_rng().gen())
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction log entry for recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionLogEntry {
    pub id: TransactionId,
    pub operation: String,
    pub started_at: SystemTime,
    pub completed: bool,
    pub rollback_actions: Vec<RollbackAction>,
}

/// Actions that can be performed during rollback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackAction {
    DeleteFile(PathBuf),
    RestoreFile { from: PathBuf, to: PathBuf },
    RestoreMetadata { path: PathBuf, metadata: FileMetadata },
}

/// Buffer size constants for optimal performance
pub const OPTIMAL_BUFFER_SIZE: usize = 64 * 1024; // 64KB
pub const SMALL_FILE_THRESHOLD: usize = 1024 * 1024; // 1MB
