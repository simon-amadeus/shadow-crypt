//! Files vertical slice - all file-related functionality.

pub mod types;
pub mod format;
pub mod detection;
pub mod hash;
pub mod operations;
pub mod io;

// Re-export commonly used types
pub use types::{FileJob, FileInfo, FileType, PlaintextData, EncryptedData};
pub use format::{TlvHeader, TlvFieldType, TlvHeaderBuilder};
pub use detection::{detect_file_type, is_encrypted_file};
pub use io::{write_encrypted_file, remove_source_file, verify_encrypted_file};
pub use hash::{ContentHash, ContentHasher, CONTENT_HASH_SIZE};
