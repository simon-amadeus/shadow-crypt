//! # DuplicateDetector Entity
//!
//! Manages content fingerprinting and duplicate detection using SHA-256 hashes.
//! Supports efficient duplicate detection across multiple search paths with
//! in-memory caching for performance optimization.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use shadow_crypt::domain::entities::duplicate_detector::DuplicateDetector;
//! use std::path::PathBuf;
//!
//! let search_paths = vec![PathBuf::from("/encrypted/files")];
//! let mut detector = DuplicateDetector::new(search_paths);
//!
//! // Calculate content hash for a file
//! let file_path = std::path::Path::new("example.txt");
//! let hash = detector.calculate_content_hash(file_path)?;
//!
//! // Check for duplicates
//! if let Some(duplicates) = detector.check_duplicate(&hash) {
//!     println!("Found {} existing files with same content", duplicates.len());
//! }
//!
//! // Add new encrypted file to database
//! let encrypted_path = PathBuf::from("example.shadow");
//! detector.add_encrypted_file(encrypted_path, hash);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Security Considerations
//!
//! - Content hashes are SHA-256, providing cryptographic integrity
//! - File I/O errors do not expose sensitive file system details  
//! - Memory usage is bounded by number of tracked files
//! - Hash calculation uses chunked reading for large files
//!
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use sha2::{Sha256, Digest};
use crate::domain::errors::{DomainError, DomainResult};
use crate::domain::utilities::content_hash::ContentHash;

/// Buffer size for chunked file reading (8KB for memory efficiency)
const BUFFER_SIZE: usize = 8192;

/// Database of content hashes mapped to file paths
/// 
/// Uses HashMap for O(1) duplicate detection performance.
/// Memory usage scales linearly with number of unique files tracked.
#[derive(Debug, Clone)]
pub struct ContentHashDatabase {
    hash_to_files: HashMap<ContentHash, Vec<PathBuf>>,
}

impl ContentHashDatabase {
    /// Create a new empty database
    pub fn new() -> Self {
        Self {
            hash_to_files: HashMap::new(),
        }
    }

    /// Add an encrypted file to the database
    /// 
    /// If the content hash already exists, the file path is added to the list
    /// of files with that hash (indicating duplicate content).
    pub fn add_encrypted_file(&mut self, file_path: PathBuf, content_hash: ContentHash) {
        self.hash_to_files
            .entry(content_hash)
            .or_insert_with(Vec::new)
            .push(file_path);
    }

    /// Check if a content hash already exists
    /// 
    /// Returns the paths of all files with matching hash, if any exist.
    /// Returns None if no files with this hash are tracked.
    pub fn check_duplicate(&self, content_hash: &ContentHash) -> Option<&Vec<PathBuf>> {
        self.hash_to_files.get(content_hash)
    }

    /// Get total number of tracked files across all hashes
    pub fn file_count(&self) -> usize {
        self.hash_to_files.values().map(|files| files.len()).sum()
    }

    /// Get total number of unique content hashes
    pub fn unique_hash_count(&self) -> usize {
        self.hash_to_files.len()
    }

    /// Remove all entries from the database
    pub fn clear(&mut self) {
        self.hash_to_files.clear();
    }

    /// Check if the database is empty
    pub fn is_empty(&self) -> bool {
        self.hash_to_files.is_empty()
    }

    /// Get an iterator over all tracked content hashes
    pub fn content_hashes(&self) -> impl Iterator<Item = &ContentHash> {
        self.hash_to_files.keys()
    }
}

impl Default for ContentHashDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages content fingerprinting and duplicate detection
///
/// Provides high-level interface for duplicate detection across multiple
/// search paths with built-in performance optimizations and error handling.
#[derive(Debug, Clone)]
pub struct DuplicateDetector {
    content_database: ContentHashDatabase,
    search_paths: Vec<PathBuf>,
}

impl DuplicateDetector {
    /// Create a new DuplicateDetector instance
    /// 
    /// # Arguments
    /// * `search_paths` - Directories to search for existing encrypted files
    pub fn new(search_paths: Vec<PathBuf>) -> Self {
        Self {
            content_database: ContentHashDatabase::new(),
            search_paths,
        }
    }

    /// Create a builder for configuring DuplicateDetector
    /// 
    /// Provides a fluent interface for configuring complex duplicate detection scenarios.
    /// Particularly useful when integrating with EncryptionService and other domain services.
    /// 
    /// # Example
    /// ```rust,no_run
    /// use shadow_crypt::domain::entities::duplicate_detector::DuplicateDetector;
    /// use std::path::PathBuf;
    /// 
    /// let detector = DuplicateDetector::builder()
    ///     .add_search_path(PathBuf::from("/encrypted/documents"))
    ///     .add_search_path(PathBuf::from("/encrypted/backups"))
    ///     .build();
    /// ```
    pub fn builder() -> DuplicateDetectorBuilder {
        DuplicateDetectorBuilder::new()
    }

    /// Add a search path for duplicate detection
    /// 
    /// Does not add duplicate paths - each path is added only once.
    pub fn add_search_path(&mut self, path: PathBuf) {
        if !self.search_paths.contains(&path) {
            self.search_paths.push(path);
        }
    }

    /// Get all configured search paths
    pub fn search_paths(&self) -> &[PathBuf] {
        &self.search_paths
    }

    /// Calculate SHA-256 content hash for a file
    /// 
    /// Uses chunked reading for memory efficiency with large files.
    /// 
    /// # Arguments
    /// * `file_path` - Path to the file to hash
    /// 
    /// # Returns
    /// * `Ok(ContentHash)` - SHA-256 hash of the file content
    /// * `Err(DomainError)` - File I/O error or other failure
    pub fn calculate_content_hash(&self, file_path: &Path) -> DomainResult<ContentHash> {
        calculate_file_content_hash(file_path)
    }

    /// Check if content already exists in any tracked files
    /// 
    /// # Arguments
    /// * `content_hash` - SHA-256 hash to search for
    /// 
    /// # Returns
    /// * `Some(paths)` - Vector of file paths with matching content
    /// * `None` - No files found with matching content
    pub fn check_duplicate(&self, content_hash: &ContentHash) -> Option<&Vec<PathBuf>> {
        self.content_database.check_duplicate(content_hash)
    }

    /// Add an encrypted file to the duplicate detection database
    /// 
    /// # Arguments
    /// * `file_path` - Path to the encrypted file
    /// * `content_hash` - SHA-256 hash of the original content
    pub fn add_encrypted_file(&mut self, file_path: PathBuf, content_hash: ContentHash) {
        self.content_database.add_encrypted_file(file_path, content_hash);
    }

    /// Scan existing encrypted files to build the database
    /// 
    /// This method will scan all configured search paths for .shadow files
    /// and extract their content hashes to build the duplicate detection database.
    /// 
    /// # Implementation Note
    /// Currently returns success immediately. Full implementation requires
    /// EncryptedFile parsing capabilities to extract ContentHash from TLV headers.
    /// This will be implemented in a future cycle when EncryptedFile I/O is ready.
    pub fn scan_existing_files(&mut self) -> DomainResult<ScanResults> {
        // TODO: Implementation will be added when EncryptedFile parsing is ready
        // Planned implementation:
        // 1. Recursively scan search_paths for *.shadow files
        // 2. Parse each file header to extract ContentHash TLV field  
        // 3. Add to content_database with add_encrypted_file()
        // 4. Return statistics about scan results
        
        Ok(ScanResults {
            scanned_files: 0,
            valid_headers: 0,
            added_hashes: 0,
            errors: Vec::new(),
        })
    }

    /// Get database statistics
    pub fn get_stats(&self) -> DatabaseStats {
        DatabaseStats {
            tracked_files: self.content_database.file_count(),
            unique_hashes: self.content_database.unique_hash_count(),
            search_paths: self.search_paths.len(),
            database_empty: self.content_database.is_empty(),
        }
    }

    /// Clear the duplicate detection database
    /// 
    /// Removes all tracked files and hashes. Search paths are preserved.
    pub fn clear_database(&mut self) {
        self.content_database.clear();
    }

    /// Check if any duplicates exist for multiple content hashes
    /// 
    /// Batch operation for efficiency when checking many hashes.
    pub fn check_multiple_duplicates(&self, content_hashes: &[ContentHash]) -> Vec<(ContentHash, Option<&Vec<PathBuf>>)> {
        content_hashes
            .iter()
            .map(|hash| (*hash, self.check_duplicate(hash)))
            .collect()
    }
}

/// Builder for configuring DuplicateDetector instances
/// 
/// Provides a fluent interface for setting up duplicate detection with complex configurations.
/// Particularly useful for integration with domain services and application workflows.
#[derive(Debug, Default)]
pub struct DuplicateDetectorBuilder {
    search_paths: Vec<PathBuf>,
}

impl DuplicateDetectorBuilder {
    /// Create a new builder instance
    pub fn new() -> Self {
        Self {
            search_paths: Vec::new(),
        }
    }

    /// Add a search path for duplicate detection
    /// 
    /// Paths are deduplicated automatically - adding the same path multiple times
    /// will only result in a single entry.
    pub fn add_search_path(mut self, path: PathBuf) -> Self {
        if !self.search_paths.contains(&path) {
            self.search_paths.push(path);
        }
        self
    }

    /// Add multiple search paths at once
    pub fn add_search_paths(mut self, paths: Vec<PathBuf>) -> Self {
        for path in paths {
            if !self.search_paths.contains(&path) {
                self.search_paths.push(path);
            }
        }
        self
    }

    /// Build the configured DuplicateDetector instance
    pub fn build(self) -> DuplicateDetector {
        DuplicateDetector::new(self.search_paths)
    }
}
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    /// Total number of files tracked across all hashes
    pub tracked_files: usize,
    /// Number of unique content hashes in the database
    pub unique_hashes: usize,
    /// Number of configured search paths
    pub search_paths: usize,
    /// True if the database contains no entries
    pub database_empty: bool,
}

/// Results from scanning existing encrypted files
#[derive(Debug, Clone)]
pub struct ScanResults {
    /// Total number of files scanned
    pub scanned_files: usize,
    /// Number of files with valid Shadow headers
    pub valid_headers: usize,
    /// Number of content hashes successfully added to database
    pub added_hashes: usize,
    /// Any errors encountered during scanning
    pub errors: Vec<String>,
}

/// Calculate SHA-256 content hash for a file
/// 
/// Uses chunked reading for memory efficiency with large files (8KB chunks).
/// Provides cryptographic-grade content fingerprinting for duplicate detection.
/// 
/// # Security Properties
/// - Uses SHA-256 for cryptographic integrity
/// - Processes files in chunks to prevent memory exhaustion
/// - Does not expose file content in error messages
/// - Resistant to timing attacks (reads entire file)
/// 
/// # Performance
/// - Memory usage: ~8KB regardless of file size
/// - Time complexity: O(file_size) with constant memory overhead
/// - Suitable for files from empty to multi-GB sizes
/// 
/// # Arguments
/// * `file_path` - Path to the file to hash
/// 
/// # Returns
/// * `Ok(ContentHash)` - 32-byte SHA-256 hash of file content
/// * `Err(DomainError)` - File I/O error (does not expose sensitive details)
/// 
/// # Example
/// ```rust,no_run
/// use shadow_crypt::domain::entities::duplicate_detector::calculate_file_content_hash;
/// use std::path::Path;
/// 
/// let hash = calculate_file_content_hash(Path::new("document.txt"))?;
/// println!("Content hash: {:?}", hash);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn calculate_file_content_hash(file_path: &Path) -> DomainResult<ContentHash> {
    let file = File::open(file_path)
        .map_err(|e| DomainError::FileSystemError(
            crate::domain::errors::FileSystemError::IoOperationFailed {
                operation: "open file for hashing".to_string(),
                reason: format!("Unable to access file: {}", e.kind()),
            }
        ))?;
    
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let bytes_read = reader.read(&mut buffer)
            .map_err(|e| DomainError::FileSystemError(
                crate::domain::errors::FileSystemError::IoOperationFailed {
                    operation: "read file for hashing".to_string(),
                    reason: format!("Unable to read file data: {}", e.kind()),
                }
            ))?;
        
        if bytes_read == 0 {
            break; // End of file reached
        }
        
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&result);
    Ok(hash_array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_content_hash_calculation() {
        // Create test file with known content
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Hello, Shadow!").unwrap();
        temp_file.flush().unwrap();

        let hash = calculate_file_content_hash(temp_file.path()).unwrap();
        assert_eq!(hash.len(), 32, "Hash should be 32 bytes");

        // Calculate again to ensure consistency
        let hash2 = calculate_file_content_hash(temp_file.path()).unwrap();
        assert_eq!(hash, hash2, "Hash should be consistent");
    }

    #[test]
    fn test_different_content_different_hash() {
        let mut temp_file1 = NamedTempFile::new().unwrap();
        temp_file1.write_all(b"Content A").unwrap();
        temp_file1.flush().unwrap();

        let mut temp_file2 = NamedTempFile::new().unwrap();
        temp_file2.write_all(b"Content B").unwrap();
        temp_file2.flush().unwrap();

        let hash1 = calculate_file_content_hash(temp_file1.path()).unwrap();
        let hash2 = calculate_file_content_hash(temp_file2.path()).unwrap();

        assert_ne!(hash1, hash2, "Different content should produce different hashes");
    }

    #[test]
    fn test_large_file_chunked_reading() {
        // Create a file larger than our buffer size
        let mut temp_file = NamedTempFile::new().unwrap();
        let large_content = vec![0x42u8; 16384]; // 16KB
        temp_file.write_all(&large_content).unwrap();
        temp_file.flush().unwrap();

        let hash = calculate_file_content_hash(temp_file.path()).unwrap();
        assert_eq!(hash.len(), 32, "Hash should be 32 bytes for large file");
    }

    #[test]
    fn test_content_hash_database_extended() {
        let mut database = ContentHashDatabase::new();
        assert!(database.is_empty());
        
        let hash1 = [0x01u8; 32];
        let hash2 = [0x02u8; 32];
        let path1 = PathBuf::from("/test/file1.shadow");
        let path2 = PathBuf::from("/test/file2.shadow");
        let path3 = PathBuf::from("/test/file3.shadow");

        // Add files
        database.add_encrypted_file(path1.clone(), hash1);
        database.add_encrypted_file(path2.clone(), hash2);
        database.add_encrypted_file(path3.clone(), hash1); // Duplicate content

        // Check statistics
        assert!(!database.is_empty());
        assert_eq!(database.file_count(), 3);
        assert_eq!(database.unique_hash_count(), 2);

        // Check duplicate detection
        let duplicates = database.check_duplicate(&hash1).unwrap();
        assert_eq!(duplicates.len(), 2);
        assert!(duplicates.contains(&path1));
        assert!(duplicates.contains(&path3));

        let no_duplicates = database.check_duplicate(&[0x99u8; 32]);
        assert!(no_duplicates.is_none());

        // Test content hashes iterator
        let hashes: Vec<_> = database.content_hashes().collect();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&&hash1));
        assert!(hashes.contains(&&hash2));

        // Test clear
        database.clear();
        assert!(database.is_empty());
        assert_eq!(database.file_count(), 0);
        assert_eq!(database.unique_hash_count(), 0);
    }

    #[test]
    fn test_duplicate_detector_extended() {
        let search_paths = vec![PathBuf::from("/test1"), PathBuf::from("/test2")];
        let mut detector = DuplicateDetector::new(search_paths.clone());

        assert_eq!(detector.search_paths(), search_paths.as_slice());

        // Add some files to the database
        let hash1 = [0x42u8; 32];
        let hash2 = [0x43u8; 32];
        let path1 = PathBuf::from("/test/file1.shadow");
        let path2 = PathBuf::from("/test/file2.shadow");
        
        detector.add_encrypted_file(path1.clone(), hash1);
        detector.add_encrypted_file(path2.clone(), hash2);

        // Check duplicate detection
        let duplicates = detector.check_duplicate(&hash1).unwrap();
        assert!(duplicates.contains(&path1));

        // Test batch duplicate checking
        let hashes_to_check = [hash1, hash2, [0x99u8; 32]];
        let results = detector.check_multiple_duplicates(&hashes_to_check);
        assert_eq!(results.len(), 3);
        assert!(results[0].1.is_some()); // hash1 found
        assert!(results[1].1.is_some()); // hash2 found  
        assert!(results[2].1.is_none());  // 0x99 not found

        // Check statistics
        let stats = detector.get_stats();
        assert_eq!(stats.tracked_files, 2);
        assert_eq!(stats.unique_hashes, 2);
        assert_eq!(stats.search_paths, 2);
        assert!(!stats.database_empty);

        // Test scan_existing_files (placeholder implementation)
        let scan_results = detector.scan_existing_files().unwrap();
        assert_eq!(scan_results.scanned_files, 0);
        assert_eq!(scan_results.valid_headers, 0);
        assert_eq!(scan_results.added_hashes, 0);
        assert!(scan_results.errors.is_empty());

        // Test clear database
        detector.clear_database();
        let stats_after_clear = detector.get_stats();
        assert_eq!(stats_after_clear.tracked_files, 0);
        assert_eq!(stats_after_clear.unique_hashes, 0);
        assert!(stats_after_clear.database_empty);
    }

    #[test]
    fn test_empty_file_hash() {
        let temp_file = NamedTempFile::new().unwrap();
        let hash = calculate_file_content_hash(temp_file.path()).unwrap();
        assert_eq!(hash.len(), 32, "Empty file should still produce valid hash");
    }

    #[test]
    fn test_duplicate_detector_builder() {
        // Test builder pattern
        let detector = DuplicateDetector::builder()
            .add_search_path(PathBuf::from("/path1"))
            .add_search_path(PathBuf::from("/path2"))
            .add_search_path(PathBuf::from("/path1")) // Duplicate - should be ignored
            .build();

        let search_paths = detector.search_paths();
        assert_eq!(search_paths.len(), 2);
        assert!(search_paths.contains(&PathBuf::from("/path1")));
        assert!(search_paths.contains(&PathBuf::from("/path2")));

        // Test add_search_paths batch method
        let detector2 = DuplicateDetector::builder()
            .add_search_paths(vec![
                PathBuf::from("/batch1"),
                PathBuf::from("/batch2"),
                PathBuf::from("/batch1"), // Duplicate
            ])
            .build();

        let search_paths2 = detector2.search_paths();
        assert_eq!(search_paths2.len(), 2);
        assert!(search_paths2.contains(&PathBuf::from("/batch1")));
        assert!(search_paths2.contains(&PathBuf::from("/batch2")));

        // Test empty builder
        let empty_detector = DuplicateDetector::builder().build();
        assert_eq!(empty_detector.search_paths().len(), 0);
    }
}