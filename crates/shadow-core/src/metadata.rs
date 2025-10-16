// shadow-core/src/metadata.rs
// File metadata and information types
// Pure data structures for file-related information

/// File metadata containing original filename and content hash
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub original_name: String,
    pub content_hash: [u8; 32],  // SHA-256
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_metadata() {
        let metadata = FileMetadata {
            original_name: "test.txt".to_string(),
            content_hash: [0u8; 32],
            size: 1024,
        };
        assert_eq!(metadata.original_name, "test.txt");
        assert_eq!(metadata.size, 1024);
    }
}