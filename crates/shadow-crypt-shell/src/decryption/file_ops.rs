use std::io::{Read, Seek, SeekFrom, Write};

use shadow_crypt_core::{
    file::FileMetadata,
    memory::{SecureKey, SecureString},
    vault::ParsedFile,
};

use crate::{
    decryption::file::{DecryptionInputFile, DecryptionOutputFile},
    errors::{WorkflowError, WorkflowResult},
    utils::read_up_to,
};

/// Creates the plaintext output file for a decrypted filename, enforcing the
/// no-traversal and no-overwrite policies.
fn create_output_file(
    filename: &SecureString,
    output_dir: &std::path::Path,
    force: bool,
) -> WorkflowResult<(std::fs::File, DecryptionOutputFile)> {
    // Reject any path traversal by taking only the bare filename component.
    // This prevents a malicious .shadow file from writing to an arbitrary path.
    let safe_name = std::path::Path::new(filename.as_str())
        .file_name()
        .ok_or_else(|| {
            WorkflowError::File("Decrypted filename contains invalid path components".to_string())
        })?;
    let safe_name_str = safe_name
        .to_str()
        .ok_or_else(|| WorkflowError::File("Decrypted filename is not valid UTF-8".to_string()))?
        .to_string();

    let output_file = DecryptionOutputFile {
        path: output_dir.join(safe_name),
        filename: safe_name_str,
    };

    // With --force, remove the existing file first (rather than truncating)
    // so a symlink at the target is never followed to clobber elsewhere.
    if force {
        match std::fs::remove_file(output_file.path.as_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }

    // create_new makes the no-overwrite check atomic: no window between an
    // exists() check and creation, and symlinks are never followed to clobber
    // an existing target.
    let f = std::fs::File::create_new(output_file.path.as_path()).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            WorkflowError::File(format!(
                "Output file '{}' already exists (use --force to overwrite)",
                output_file.filename
            ))
        } else {
            WorkflowError::Io(e)
        }
    })?;

    Ok((f, output_file))
}

/// Restores preserved metadata onto the decrypted file. Applied after the
/// content is written, since writing would bump the mtime again.
fn apply_metadata(f: &std::fs::File, metadata: &FileMetadata) -> WorkflowResult<()> {
    #[cfg(unix)]
    if let Some(mode) = metadata.mode() {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))?;
    }
    if let Some(mtime) = metadata.mtime() {
        f.set_modified(mtime)?;
    }
    Ok(())
}

/// Streams the encrypted input file's content through the parsed file's
/// decryptor into the plaintext output file, then restores the preserved
/// metadata. Memory is bounded by the format's chunk size (formats without
/// chunking are decrypted as one piece). A partially written output is
/// removed on failure.
pub fn stream_decrypt_file(
    file: &DecryptionInputFile,
    parsed: &ParsedFile,
    key: &SecureKey,
    metadata: &FileMetadata,
    output_dir: &std::path::Path,
    force: bool,
) -> WorkflowResult<DecryptionOutputFile> {
    let (mut out, output_file) = create_output_file(metadata.filename(), output_dir, force)?;

    let result = (|| -> WorkflowResult<()> {
        let mut reader = std::fs::File::open(&file.path)?;
        reader.seek(SeekFrom::Start(parsed.header_length() as u64))?;

        let mut decryptor = parsed.content_decryptor(key);
        match decryptor.chunk_len() {
            // The whole content is a single AEAD message: feed it at once.
            None => {
                let mut content = Vec::new();
                reader.read_to_end(&mut content)?;
                out.write_all(decryptor.decrypt_chunk(&content, true)?.as_slice())?;
            }
            // Chunked content: double-buffered read, a chunk is final when
            // the read after it returns nothing.
            Some(chunk_len) => {
                let mut current = vec![0u8; chunk_len];
                let mut next = vec![0u8; chunk_len];
                let mut current_len = read_up_to(&mut reader, &mut current)?;
                loop {
                    let next_len = read_up_to(&mut reader, &mut next)?;
                    let is_last = next_len == 0;
                    out.write_all(
                        decryptor
                            .decrypt_chunk(&current[..current_len], is_last)?
                            .as_slice(),
                    )?;
                    if is_last {
                        break;
                    }
                    std::mem::swap(&mut current, &mut next);
                    current_len = next_len;
                }
            }
        }

        apply_metadata(&out, metadata)?;
        Ok(())
    })();

    match result {
        Ok(()) => Ok(output_file),
        Err(e) => {
            let _ = std::fs::remove_file(&output_file.path);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_crypt_core::memory::SecureBytes;
    use std::fs;

    fn write_output(
        filename: &str,
        content: &[u8],
        output_dir: &std::path::Path,
        force: bool,
    ) -> WorkflowResult<DecryptionOutputFile> {
        let filename = SecureString::new(filename.to_string());
        let content = SecureBytes::new(content.to_vec());
        let (mut f, output_file) = create_output_file(&filename, output_dir, force)?;
        f.write_all(content.as_slice())?;
        Ok(output_file)
    }

    #[test]
    fn test_create_and_write_output_file() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        let output = write_output("test.txt", b"test content", temp_dir.path(), false).unwrap();
        assert_eq!(output.filename, "test.txt");
        assert_eq!(fs::read(&output.path).unwrap(), b"test content");
    }

    #[test]
    fn test_output_file_path_traversal_rejected() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        for malicious_name in &["../../etc/passwd", "../sibling", "/abs/path", ".."] {
            let result = write_output(malicious_name, b"evil", temp_dir.path(), false);

            match malicious_name {
                &".." => {
                    assert!(
                        result.is_err(),
                        "Expected error for filename '{malicious_name}'"
                    );
                }
                _ => {
                    // file_name() strips leading directories, so it succeeds
                    // but writes into temp_dir, not to the traversed path
                    if let Ok(output) = result {
                        assert!(
                            output.path.starts_with(temp_dir.path()),
                            "Output escaped temp_dir for '{malicious_name}'"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_output_file_no_overwrite() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        let output_path = temp_dir.path().join("test.txt");
        let existing_content = b"existing content";
        fs::write(&output_path, existing_content).unwrap();

        let result = write_output("test.txt", b"new content", temp_dir.path(), false);
        assert!(result.is_err());
        if let Err(WorkflowError::File(msg)) = result {
            assert!(msg.contains("already exists"));
        } else {
            panic!("Expected File error");
        }

        // Check existing content unchanged
        assert_eq!(fs::read(&output_path).unwrap(), existing_content);
    }

    #[test]
    fn test_output_file_force_overwrites() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        let output_path = temp_dir.path().join("test.txt");
        fs::write(&output_path, b"existing content").unwrap();

        let output = write_output("test.txt", b"new content", temp_dir.path(), true).unwrap();
        assert_eq!(fs::read(&output.path).unwrap(), b"new content");
    }

    #[test]
    fn test_output_file_force_without_existing_file() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        let output = write_output("test.txt", b"content", temp_dir.path(), true).unwrap();
        assert_eq!(fs::read(&output.path).unwrap(), b"content");
    }
}
