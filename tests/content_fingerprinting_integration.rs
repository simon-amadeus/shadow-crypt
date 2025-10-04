use shadow_crypt::domain::entities::duplicate_detector::{DuplicateDetector, calculate_file_content_hash};
use shadow_crypt::domain::entities::tlv_header::TlvHeader;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

#[test]
fn test_content_fingerprinting_workflow() {
    // Setup test environment
    let temp_dir = TempDir::new().unwrap();
    let search_paths = vec![temp_dir.path().to_path_buf()];
    let mut detector = DuplicateDetector::new(search_paths);

    // Create first file with specific content
    let mut file1 = NamedTempFile::new_in(temp_dir.path()).unwrap();
    file1.write_all(b"This is test content for file 1").unwrap();
    file1.flush().unwrap();

    // Create second file with same content (should be duplicate)
    let mut file2 = NamedTempFile::new_in(temp_dir.path()).unwrap();
    file2.write_all(b"This is test content for file 1").unwrap();
    file2.flush().unwrap();

    // Create third file with different content
    let mut file3 = NamedTempFile::new_in(temp_dir.path()).unwrap();
    file3.write_all(b"This is different content for file 3").unwrap();
    file3.flush().unwrap();

    // Calculate content hashes
    let hash1 = calculate_file_content_hash(file1.path()).unwrap();
    let hash2 = calculate_file_content_hash(file2.path()).unwrap();
    let hash3 = calculate_file_content_hash(file3.path()).unwrap();

    // Verify same content produces same hash
    assert_eq!(hash1, hash2, "Files with same content should have same hash");
    assert_ne!(hash1, hash3, "Files with different content should have different hashes");

    // Simulate adding encrypted files to the database
    let encrypted_file1_path = temp_dir.path().join("file1.shadow");
    let encrypted_file3_path = temp_dir.path().join("file3.shadow");

    detector.add_encrypted_file(encrypted_file1_path.clone(), hash1);
    detector.add_encrypted_file(encrypted_file3_path.clone(), hash3);

    // Check for duplicates before encrypting file2
    let duplicates = detector.check_duplicate(&hash2);
    assert!(duplicates.is_some(), "Should detect duplicate content");
    let duplicate_paths = duplicates.unwrap();
    assert_eq!(duplicate_paths.len(), 1, "Should find one duplicate");
    assert!(duplicate_paths.contains(&encrypted_file1_path), "Should find file1 as duplicate");

    // Check that unique content has no duplicates
    let no_duplicates = detector.check_duplicate(&hash3);
    assert!(no_duplicates.is_some(), "Should have entry for hash3");
    assert_eq!(no_duplicates.unwrap().len(), 1, "Should have only one file with this hash");

    // Verify database statistics
    let stats = detector.get_stats();
    assert_eq!(stats.tracked_files, 2, "Should track 2 files");
    assert_eq!(stats.unique_hashes, 2, "Should have 2 unique hashes");
    assert_eq!(stats.search_paths, 1, "Should have 1 search path");
}

#[test]
fn test_tlv_header_content_hash_integration() {
    // Create test file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"Test content for TLV integration").unwrap();
    temp_file.flush().unwrap();

    // Calculate content hash
    let content_hash = calculate_file_content_hash(temp_file.path()).unwrap();

    // Create TLV header and store content hash
    let mut header = TlvHeader::new();
    header.set_content_hash(content_hash);
    header.set_original_filename("test_file.txt");

    // Verify content hash can be retrieved
    let retrieved_hash = header.content_hash().unwrap();
    assert_eq!(content_hash, retrieved_hash, "Content hash should be preserved in TLV header");

    // Verify other fields are preserved
    assert_eq!(header.original_filename(), Some("test_file.txt".to_string()));
}

#[test]
fn test_duplicate_detection_performance() {
    // Test with multiple files to ensure performance is reasonable
    let temp_dir = TempDir::new().unwrap();
    let mut detector = DuplicateDetector::new(vec![temp_dir.path().to_path_buf()]);

    let mut hashes = Vec::new();
    let num_files = 100;

    // Create many files with unique content
    for i in 0..num_files {
        let mut temp_file = NamedTempFile::new_in(temp_dir.path()).unwrap();
        temp_file.write_all(format!("Unique content for file {}", i).as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let hash = calculate_file_content_hash(temp_file.path()).unwrap();
        hashes.push(hash);

        let encrypted_path = temp_dir.path().join(format!("file{}.shadow", i));
        detector.add_encrypted_file(encrypted_path, hash);
    }

    // Verify all hashes are unique
    let stats = detector.get_stats();
    assert_eq!(stats.tracked_files, num_files, "Should track all files");
    assert_eq!(stats.unique_hashes, num_files, "All files should have unique hashes");

    // Test duplicate detection for each hash
    for hash in &hashes {
        let duplicates = detector.check_duplicate(hash);
        assert!(duplicates.is_some(), "Should find entry for each hash");
        assert_eq!(duplicates.unwrap().len(), 1, "Each hash should have exactly one file");
    }

    // Test non-existent hash
    let fake_hash = [0x99u8; 32];
    let no_match = detector.check_duplicate(&fake_hash);
    assert!(no_match.is_none(), "Should not find non-existent hash");
}

#[test]
fn test_empty_and_large_files() {
    // Test empty file
    let empty_file = NamedTempFile::new().unwrap();
    let empty_hash = calculate_file_content_hash(empty_file.path()).unwrap();
    assert_eq!(empty_hash.len(), 32, "Empty file should produce valid hash");

    // Test large file (simulate with repeated content)
    let mut large_file = NamedTempFile::new().unwrap();
    let chunk = vec![0x42u8; 8192]; // 8KB chunk
    for _ in 0..10 {
        large_file.write_all(&chunk).unwrap(); // Total: 80KB
    }
    large_file.flush().unwrap();

    let large_hash = calculate_file_content_hash(large_file.path()).unwrap();
    assert_eq!(large_hash.len(), 32, "Large file should produce valid hash");
    
    // Different large files should have different hashes
    let mut large_file2 = NamedTempFile::new().unwrap();
    let chunk2 = vec![0x43u8; 8192]; // Different content
    for _ in 0..10 {
        large_file2.write_all(&chunk2).unwrap();
    }
    large_file2.flush().unwrap();

    let large_hash2 = calculate_file_content_hash(large_file2.path()).unwrap();
    assert_ne!(large_hash, large_hash2, "Different large files should have different hashes");
}