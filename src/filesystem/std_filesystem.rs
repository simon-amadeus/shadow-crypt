use crate::error::EncryptionError;
use crate::traits::FileSystem;
use crate::types::{FileMetadata, Header, OPTIMAL_BUFFER_SIZE};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Standard filesystem implementation
#[derive(Clone)]
pub struct StdFileSystem;

impl StdFileSystem {
    pub fn new() -> Self {
        Self
    }

    fn get_system_metadata(&self, path: &Path) -> Result<FileMetadata, EncryptionError> {
        let metadata = std::fs::metadata(path)?;
        
        Ok(FileMetadata {
            permissions: {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.permissions().mode()
                }
                #[cfg(not(unix))]
                {
                    if metadata.permissions().readonly() { 0o444 } else { 0o644 }
                }
            },
            created: metadata.created().unwrap_or(SystemTime::UNIX_EPOCH),
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            accessed: metadata.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
        })
    }

    fn set_system_metadata(&self, path: &Path, metadata: &FileMetadata) -> Result<(), EncryptionError> {
        // Set timestamps
        if let Ok(()) = filetime::set_file_times(
            path,
            filetime::FileTime::from_system_time(metadata.accessed),
            filetime::FileTime::from_system_time(metadata.modified),
        ) {
            // Timestamp setting succeeded
        }

        // Set permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(metadata.permissions);
            std::fs::set_permissions(path, permissions)?;
        }

        Ok(())
    }
}

impl Default for StdFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSystem for StdFileSystem {
    fn read_file(&self, path: &Path) -> Result<Box<dyn Read>, EncryptionError> {
        let file = File::open(path)?;
        Ok(Box::new(BufReader::with_capacity(OPTIMAL_BUFFER_SIZE, file)))
    }

    fn write_file(&self, path: &Path, content: &mut dyn Read) -> Result<(), EncryptionError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(OPTIMAL_BUFFER_SIZE, file);
        
        let mut buffer = vec![0u8; OPTIMAL_BUFFER_SIZE];
        loop {
            let bytes_read = content.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            writer.write_all(&buffer[..bytes_read])?;
        }
        
        writer.flush()?;
        Ok(())
    }

    fn traverse_directory(&self, root: &Path, recursive: bool) -> Result<Vec<PathBuf>, EncryptionError> {
        let mut files = Vec::new();
        
        if recursive {
            for entry in walkdir::WalkDir::new(root) {
                let entry = entry.map_err(|e| EncryptionError::FileSystemError(
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                ))?;
                
                if entry.file_type().is_file() {
                    files.push(entry.path().to_path_buf());
                }
            }
        } else {
            for entry in std::fs::read_dir(root)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_file() {
                    files.push(path);
                }
            }
        }
        
        Ok(files)
    }

    fn read_file_range(&self, path: &Path, start: u64, length: u64) -> Result<Box<dyn Read>, EncryptionError> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(start))?;
        
        let limited_reader = file.take(length);
        Ok(Box::new(BufReader::new(limited_reader)))
    }

    fn write_encrypted_file(&self, path: &Path, header: Header, content: &mut dyn Read) -> Result<(), EncryptionError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(OPTIMAL_BUFFER_SIZE, file);
        
        // Write header
        let header_bytes = bincode::serialize(&header)?;
        let header_length = header_bytes.len() as u32;
        writer.write_all(&header_length.to_le_bytes())?;
        writer.write_all(&header_bytes)?;
        
        // Write content
        let mut buffer = vec![0u8; OPTIMAL_BUFFER_SIZE];
        loop {
            let bytes_read = content.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            writer.write_all(&buffer[..bytes_read])?;
        }
        
        writer.flush()?;
        Ok(())
    }

    fn read_encrypted_file(&self, path: &Path) -> Result<(Header, Box<dyn Read>), EncryptionError> {
        let mut file = File::open(path)?;
        
        // Read header length
        let mut header_length_bytes = [0u8; 4];
        file.read_exact(&mut header_length_bytes)?;
        let header_length = u32::from_le_bytes(header_length_bytes) as usize;
        
        // Read header
        let mut header_bytes = vec![0u8; header_length];
        file.read_exact(&mut header_bytes)?;
        let header: Header = bincode::deserialize(&header_bytes)?;
        
        if !header.is_valid() {
            return Err(EncryptionError::InvalidFileFormat);
        }
        
        // Return remaining file content
        Ok((header, Box::new(BufReader::with_capacity(OPTIMAL_BUFFER_SIZE, file))))
    }

    fn read_header_only(&self, path: &Path) -> Result<Header, EncryptionError> {
        let mut file = File::open(path)?;
        
        // Read header length
        let mut header_length_bytes = [0u8; 4];
        file.read_exact(&mut header_length_bytes)?;
        let header_length = u32::from_le_bytes(header_length_bytes) as usize;
        
        // Read header
        let mut header_bytes = vec![0u8; header_length];
        file.read_exact(&mut header_bytes)?;
        let header: Header = bincode::deserialize(&header_bytes)?;
        
        if !header.is_valid() {
            return Err(EncryptionError::InvalidFileFormat);
        }
        
        Ok(header)
    }

    fn get_file_metadata(&self, path: &Path) -> Result<FileMetadata, EncryptionError> {
        self.get_system_metadata(path)
    }

    fn set_file_metadata(&self, path: &Path, metadata: &FileMetadata) -> Result<(), EncryptionError> {
        self.set_system_metadata(path, metadata)
    }

    fn atomic_write(&self, path: &Path, content: &mut dyn Read) -> Result<(), EncryptionError> {
        use tempfile::NamedTempFile;
        
        let temp_file = if let Some(parent) = path.parent() {
            NamedTempFile::new_in(parent)?
        } else {
            NamedTempFile::new()?
        };
        
        {
            let mut writer = BufWriter::with_capacity(OPTIMAL_BUFFER_SIZE, &temp_file);
            let mut buffer = vec![0u8; OPTIMAL_BUFFER_SIZE];
            
            loop {
                let bytes_read = content.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                writer.write_all(&buffer[..bytes_read])?;
            }
            
            writer.flush()?;
        }
        
        temp_file.persist(path)
            .map_err(|e| EncryptionError::FileSystemError(e.error))?;
        
        Ok(())
    }

    fn atomic_rename(&self, old: &Path, new: &Path) -> Result<(), EncryptionError> {
        std::fs::rename(old, new)?;
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    #[test]
    fn test_read_write_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let fs = StdFileSystem::new();

        let content = b"Hello, World!";
        let mut content_reader = Cursor::new(content);

        // Write file
        fs.write_file(&file_path, &mut content_reader).unwrap();

        // Read file
        let mut reader = fs.read_file(&file_path).unwrap();
        let mut read_content = Vec::new();
        reader.read_to_end(&mut read_content).unwrap();

        assert_eq!(content, read_content.as_slice());
    }

    #[test]
    fn test_directory_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let fs = StdFileSystem::new();

        // Create test files
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("subdir").join("file2.txt");
        
        std::fs::create_dir_all(file2.parent().unwrap()).unwrap();
        std::fs::write(&file1, "content1").unwrap();
        std::fs::write(&file2, "content2").unwrap();

        // Test non-recursive traversal
        let files = fs.traverse_directory(temp_dir.path(), false).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files.contains(&file1));

        // Test recursive traversal
        let files = fs.traverse_directory(temp_dir.path(), true).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.contains(&file1));
        assert!(files.contains(&file2));
    }

    #[test]
    fn test_atomic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("atomic_test.txt");
        let fs = StdFileSystem::new();

        let content = b"Atomic content";
        let mut content_reader = Cursor::new(content);

        // Test atomic write
        fs.atomic_write(&file_path, &mut content_reader).unwrap();
        
        // Verify content
        let mut reader = fs.read_file(&file_path).unwrap();
        let mut read_content = Vec::new();
        reader.read_to_end(&mut read_content).unwrap();
        assert_eq!(content, read_content.as_slice());

        // Test atomic rename
        let new_path = temp_dir.path().join("renamed_file.txt");
        fs.atomic_rename(&file_path, &new_path).unwrap();
        
        assert!(!file_path.exists());
        assert!(new_path.exists());
    }
}
