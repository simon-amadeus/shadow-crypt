//! # FileRepository Interface
//!
//! Abstracts file system operations for testability and flexibility.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::Path;
use std::time::SystemTime;

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// File metadata extracted from filesystem
#[derive(Debug, Clone, PartialEq)]
pub struct FileMetadata {
    pub original_filename: String,
    pub file_size: u64,
    pub modified_time: SystemTime,
    pub created_time: Option<SystemTime>,
    pub file_type: FileType,
}

/// Types of files supported
#[derive(Debug, Clone, PartialEq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Other,
}

/// Abstracts file system operations with atomic operations and secure deletion
pub trait FileRepository: Send + Sync {
    /// Read file contents
    fn read_file(&self, path: &Path) -> CryptoResult<Vec<u8>>;
    
    /// Write file contents
    fn write_file(&self, path: &Path, content: &[u8]) -> CryptoResult<()>;
    
    /// Write file atomically (using temporary file + rename)
    fn write_file_atomic(&self, path: &Path, content: &[u8]) -> CryptoResult<()>;
    
    /// Securely delete file with content overwriting
    fn delete_file_secure(&self, path: &Path) -> CryptoResult<()>;
    
    /// Check if file exists
    fn file_exists(&self, path: &Path) -> bool;
    
    /// Extract file metadata
    fn file_metadata(&self, path: &Path) -> CryptoResult<FileMetadata>;
}

/// Mock implementation for testing
#[derive(Debug)]
pub struct MockFileRepository {
    /// In-memory filesystem simulation
    files: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
    /// Track operations for verification
    operations: std::sync::Arc<std::sync::Mutex<Vec<FileOperation>>>,
    /// Control failure behavior for testing
    should_fail: std::sync::Arc<std::sync::Mutex<bool>>,
    /// Failure error message
    failure_message: std::sync::Arc<std::sync::Mutex<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileOperation {
    Read(String),
    Write(String, usize), // path, content length
    WriteAtomic(String, usize),
    DeleteSecure(String),
    CheckExists(String),
    GetMetadata(String),
}

impl Default for MockFileRepository {
    fn default() -> Self {
        Self {
            files: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            operations: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            should_fail: std::sync::Arc::new(std::sync::Mutex::new(false)),
            failure_message: std::sync::Arc::new(std::sync::Mutex::new(String::new())),
        }
    }
}

impl MockFileRepository {
    /// Create new mock repository
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Add file to mock filesystem
    pub fn add_file(&mut self, path: impl ToString, content: Vec<u8>) {
        if let Ok(mut files) = self.files.lock() {
            files.insert(path.to_string(), content);
        }
    }
    
    /// Get operation history for verification
    pub fn operations(&self) -> Vec<FileOperation> {
        self.operations.lock().map(|ops| ops.clone()).unwrap_or_default()
    }
    
    /// Configure to fail next operation
    pub fn set_should_fail(&mut self, should_fail: bool, message: impl ToString) {
        if let Ok(mut fail_flag) = self.should_fail.lock() {
            *fail_flag = should_fail;
        }
        if let Ok(mut fail_msg) = self.failure_message.lock() {
            *fail_msg = message.to_string();
        }
    }
    
    /// Clear operation history
    pub fn clear_operations(&mut self) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.clear();
        }
    }
    
    /// Check if file exists in mock filesystem
    pub fn has_file(&self, path: &str) -> bool {
        self.files.lock()
            .map(|files| files.contains_key(path))
            .unwrap_or(false)
    }
    
    /// Get file content from mock filesystem
    pub fn get_file_content(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().ok()
            .and_then(|files| files.get(path).cloned())
    }
}

impl FileRepository for MockFileRepository {
    fn read_file(&self, path: &Path) -> CryptoResult<Vec<u8>> {
        let path_str = path.to_string_lossy().to_string();
        
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(FileOperation::Read(path_str.clone()));
        }
        
        if let Ok(should_fail) = self.should_fail.lock() {
            if *should_fail {
                let msg = self.failure_message.lock()
                    .map(|m| m.clone())
                    .unwrap_or_else(|_| "Mock failure".to_string());
                return Err(msg.into());
            }
        }
        
        self.files.lock()
            .map_err(|_| "Lock error".into())
            .and_then(|files| {
                files.get(&path_str)
                    .cloned()
                    .ok_or_else(|| format!("File not found: {}", path_str).into())
            })
    }
    
    fn write_file(&self, path: &Path, content: &[u8]) -> CryptoResult<()> {
        let path_str = path.to_string_lossy().to_string();
        
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(FileOperation::Write(path_str.clone(), content.len()));
        }
        
        if let Ok(should_fail) = self.should_fail.lock() {
            if *should_fail {
                let msg = self.failure_message.lock()
                    .map(|m| m.clone())
                    .unwrap_or_else(|_| "Mock failure".to_string());
                return Err(msg.into());
            }
        }
        
        if let Ok(mut files) = self.files.lock() {
            files.insert(path_str, content.to_vec());
        }
        
        Ok(())
    }
    
    fn write_file_atomic(&self, path: &Path, content: &[u8]) -> CryptoResult<()> {
        let path_str = path.to_string_lossy().to_string();
        
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(FileOperation::WriteAtomic(path_str.clone(), content.len()));
        }
        
        if let Ok(should_fail) = self.should_fail.lock() {
            if *should_fail {
                let msg = self.failure_message.lock()
                    .map(|m| m.clone())
                    .unwrap_or_else(|_| "Mock failure".to_string());
                return Err(msg.into());
            }
        }
        
        // Mock atomic write as regular write
        if let Ok(mut files) = self.files.lock() {
            files.insert(path_str, content.to_vec());
        }
        
        Ok(())
    }
    
    fn delete_file_secure(&self, path: &Path) -> CryptoResult<()> {
        let path_str = path.to_string_lossy().to_string();
        
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(FileOperation::DeleteSecure(path_str.clone()));
        }
        
        if let Ok(should_fail) = self.should_fail.lock() {
            if *should_fail {
                let msg = self.failure_message.lock()
                    .map(|m| m.clone())
                    .unwrap_or_else(|_| "Mock failure".to_string());
                return Err(msg.into());
            }
        }
        
        if let Ok(mut files) = self.files.lock() {
            files.remove(&path_str);
        }
        
        Ok(())
    }
    
    fn file_exists(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_string();
        
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(FileOperation::CheckExists(path_str.clone()));
        }
        
        self.files.lock()
            .map(|files| files.contains_key(&path_str))
            .unwrap_or(false)
    }
    
    fn file_metadata(&self, path: &Path) -> CryptoResult<FileMetadata> {
        let path_str = path.to_string_lossy().to_string();
        
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(FileOperation::GetMetadata(path_str.clone()));
        }
        
        if let Ok(should_fail) = self.should_fail.lock() {
            if *should_fail {
                let msg = self.failure_message.lock()
                    .map(|m| m.clone())
                    .unwrap_or_else(|_| "Mock failure".to_string());
                return Err(msg.into());
            }
        }
        
        if let Ok(files) = self.files.lock() {
            if let Some(content) = files.get(&path_str) {
                Ok(FileMetadata {
                    original_filename: path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    file_size: content.len() as u64,
                    modified_time: SystemTime::now(),
                    created_time: Some(SystemTime::now()),
                    file_type: FileType::Regular,
                })
            } else {
                Err(format!("File not found: {}", path_str).into())
            }
        } else {
            Err("Lock error".into())
        }
    }
}