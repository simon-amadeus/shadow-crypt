//! Unit tests for domain entities
//! Tests the core business logic and behavior of domain entities

#[cfg(test)]
mod file_metadata_tests {
    use super::super::file_metadata::{FileMetadata, FileType};
    use std::time::SystemTime;

    #[test]
    fn test_file_metadata_creation() {
        let metadata = FileMetadata {
            original_filename: "test.txt".to_string(),
            file_size: 1024,
            modified_time: SystemTime::now(),
            created_time: Some(SystemTime::now()),
            file_type: FileType::Regular,
        };

        assert_eq!(metadata.original_filename, "test.txt");
        assert_eq!(metadata.file_size, 1024);
        assert!(matches!(metadata.file_type, FileType::Regular));
        assert!(metadata.created_time.is_some());
    }
}

#[cfg(test)]
mod tlv_header_tests {
    use super::super::tlv_header::TlvHeader;

    #[test]
    fn test_header_creation_and_basic_operations() {
        let mut header = TlvHeader::new();
        
        assert_eq!(header.magic_number(), &TlvHeader::MAGIC_NUMBER);
        assert_eq!(header.version(), TlvHeader::VERSION);
        assert!(header.is_valid_shadow_file());
        
        // Test filename operations
        assert!(header.original_filename().is_none());
        header.set_original_filename("test.txt");
        assert_eq!(header.original_filename(), Some("test.txt".to_string()));
    }

    #[test]
    fn test_content_hash_operations() {
        let mut header = TlvHeader::new();
        let test_hash = [42u8; 32];
        
        assert!(header.content_hash().is_none());
        header.set_content_hash(test_hash);
        assert_eq!(header.content_hash(), Some(test_hash));
    }

    #[test]
    fn test_algorithm_id_operations() {
        let mut header = TlvHeader::new();
        
        assert!(header.algorithm_id().is_none());
        header.set_algorithm_id(1);
        assert_eq!(header.algorithm_id(), Some(1));
    }
}

#[cfg(test)]
mod crypto_session_tests {
    use super::super::crypto_session::CryptoSession;
    use super::super::algorithm_id::AlgorithmId;

    #[test]
    fn test_crypto_session_creation() {
        let salt = [0u8; 32];
        let session = CryptoSession::new("password123", salt, AlgorithmId::XChaCha20Poly1305);
        
        assert!(session.is_ok());
        let session = session.unwrap();
        assert_eq!(session.algorithm(), AlgorithmId::XChaCha20Poly1305);
        assert_eq!(session.salt(), &salt);
        
        // Verify key material is generated
        assert_eq!(session.encryption_key().len(), 32);
        assert_eq!(session.obfuscation_key().len(), 32);
    }
}

#[cfg(test)]
mod duplicate_detector_tests {
    use super::super::duplicate_detector::DuplicateDetector;
    use std::path::PathBuf;

    #[test]
    fn test_duplicate_detector_creation() {
        let search_paths = vec![PathBuf::from("/test/path")];
        let detector = DuplicateDetector::new(search_paths.clone());
        
        assert_eq!(detector.search_paths(), &search_paths);
        
        let stats = detector.get_stats();
        assert_eq!(stats.tracked_files, 0);
        assert_eq!(stats.unique_hashes, 0);
        assert_eq!(stats.search_paths, 1);
        assert!(stats.database_empty);
    }

    #[test]
    fn test_duplicate_detection_workflow() {
        let mut detector = DuplicateDetector::new(vec![]);
        let test_hash = [42u8; 32];
        let file_path = PathBuf::from("test.shadow");
        
        // No duplicates initially
        assert!(detector.check_duplicate(&test_hash).is_none());
        
        // Add a file
        detector.add_encrypted_file(file_path.clone(), test_hash);
        
        // Should now find duplicate
        let duplicates = detector.check_duplicate(&test_hash);
        assert!(duplicates.is_some());
        assert_eq!(duplicates.unwrap(), &vec![file_path]);
        
        // Stats should reflect the addition
        let stats = detector.get_stats();
        assert_eq!(stats.tracked_files, 1);
        assert_eq!(stats.unique_hashes, 1);
        assert!(!stats.database_empty);
    }
}