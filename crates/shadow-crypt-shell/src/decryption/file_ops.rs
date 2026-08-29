use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use shadow_crypt_core::{
    archive::{ArchiveEvent, ArchiveParser},
    file::{ContentKind, FileMetadata},
    memory::{SecureKey, SecureString},
    vault::{ContentDecryptor, ParsedFile},
};

use crate::{
    decryption::file::{DecryptionInputFile, DecryptionOutputFile},
    errors::{WorkflowError, WorkflowResult},
    utils::{read_up_to, sanitize_relative_path},
};

/// Opens a fresh file at `path`, enforcing the no-overwrite policy.
fn open_new_file(path: &Path, display_name: &str, force: bool) -> WorkflowResult<std::fs::File> {
    // With --force, remove the existing file first (rather than truncating)
    // so a symlink at the target is never followed to clobber elsewhere.
    if force {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }

    // create_new makes the no-overwrite check atomic: no window between an
    // exists() check and creation, and symlinks are never followed to clobber
    // an existing target.
    std::fs::File::create_new(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            WorkflowError::File(format!(
                "Output file '{}' already exists (use --force to overwrite)",
                display_name
            ))
        } else {
            WorkflowError::Io(e)
        }
    })
}

/// Creates the plaintext output file for a decrypted filename, enforcing the
/// no-traversal and no-overwrite policies. Multi-component names (from
/// recursive encryption) recreate their directories under `output_dir`.
fn create_output_file(
    filename: &SecureString,
    output_dir: &Path,
    force: bool,
) -> WorkflowResult<(std::fs::File, DecryptionOutputFile)> {
    let safe_rel = sanitize_relative_path(filename.as_str())?;
    let path = output_dir.join(&safe_rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let display_name = safe_rel.to_string_lossy().into_owned();
    let f = open_new_file(&path, &display_name, force)?;

    Ok((
        f,
        DecryptionOutputFile {
            path,
            filename: display_name,
        },
    ))
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

/// Feeds the encrypted file's content ciphertext (everything after the
/// header) through the decryptor, passing each decrypted piece to `sink`.
fn pump_content(
    file: &DecryptionInputFile,
    parsed: &ParsedFile,
    decryptor: &mut ContentDecryptor<'_>,
    mut sink: impl FnMut(&[u8]) -> WorkflowResult<()>,
) -> WorkflowResult<()> {
    let mut reader = std::fs::File::open(&file.path)?;
    reader.seek(SeekFrom::Start(parsed.header_length() as u64))?;

    match decryptor.chunk_len() {
        // The whole content is a single AEAD message: feed it at once.
        None => {
            let mut content = Vec::new();
            reader.read_to_end(&mut content)?;
            sink(decryptor.decrypt_chunk(&content, true)?.as_slice())?;
        }
        // Chunked content: double-buffered read, a chunk is final when the
        // read after it returns nothing.
        Some(chunk_len) => {
            let mut current = vec![0u8; chunk_len];
            let mut next = vec![0u8; chunk_len];
            let mut current_len = read_up_to(&mut reader, &mut current)?;
            loop {
                let next_len = read_up_to(&mut reader, &mut next)?;
                let is_last = next_len == 0;
                sink(
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
    Ok(())
}

/// Streams the encrypted input file's content into plaintext output: a
/// single file, or an extracted directory tree when the metadata marks the
/// content as an archive. Preserved metadata is restored afterwards. Memory
/// is bounded by the format's chunk size (formats without chunking are
/// decrypted as one piece).
pub fn stream_decrypt_file(
    file: &DecryptionInputFile,
    parsed: &ParsedFile,
    key: &SecureKey,
    metadata: &FileMetadata,
    output_dir: &std::path::Path,
    force: bool,
) -> WorkflowResult<DecryptionOutputFile> {
    match metadata.kind() {
        ContentKind::File => {
            stream_decrypt_single_file(file, parsed, key, metadata, output_dir, force)
        }
        ContentKind::Archive => extract_archive(file, parsed, key, metadata, output_dir, force),
    }
}

/// Single-file case: the content stream is the file's bytes. A partially
/// written output is removed on failure.
fn stream_decrypt_single_file(
    file: &DecryptionInputFile,
    parsed: &ParsedFile,
    key: &SecureKey,
    metadata: &FileMetadata,
    output_dir: &std::path::Path,
    force: bool,
) -> WorkflowResult<DecryptionOutputFile> {
    let (mut out, output_file) = create_output_file(metadata.filename(), output_dir, force)?;

    let result = (|| -> WorkflowResult<()> {
        let mut decryptor = parsed.content_decryptor(key);
        pump_content(file, parsed, &mut decryptor, |plaintext| {
            out.write_all(plaintext)?;
            Ok(())
        })?;
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

/// Archive case: the content stream is a directory tree, extracted under
/// `output_dir/<archive name>`. Already-completed entries are kept on
/// failure (they are valid files); only the entry being written is removed.
fn extract_archive(
    file: &DecryptionInputFile,
    parsed: &ParsedFile,
    key: &SecureKey,
    metadata: &FileMetadata,
    output_dir: &std::path::Path,
    force: bool,
) -> WorkflowResult<DecryptionOutputFile> {
    let root_rel = sanitize_relative_path(metadata.filename().as_str())?;
    let root = output_dir.join(&root_rel);
    let display_name = root_rel.to_string_lossy().into_owned();

    if root.symlink_metadata().is_ok() {
        if !force {
            return Err(WorkflowError::File(format!(
                "Output directory '{}' already exists (use --force to extract into it)",
                display_name
            )));
        }
        if !root.is_dir() {
            return Err(WorkflowError::File(format!(
                "Output path '{}' exists and is not a directory",
                display_name
            )));
        }
    } else {
        std::fs::create_dir_all(&root)?;
    }

    let mut parser = ArchiveParser::new();
    // (open handle, on-disk path, entry metadata) of the file being written.
    let mut current: Option<(std::fs::File, PathBuf, FileMetadata)> = None;
    let mut directory_metas: Vec<(PathBuf, FileMetadata)> = Vec::new();

    let result = (|| -> WorkflowResult<()> {
        let mut decryptor = parsed.content_decryptor(key);
        pump_content(file, parsed, &mut decryptor, |plaintext| {
            parser.feed(plaintext);
            while let Some(event) = parser.next_event()? {
                match event {
                    ArchiveEvent::Directory { metadata } => {
                        let path = root.join(sanitize_relative_path(metadata.filename().as_str())?);
                        std::fs::create_dir_all(&path)?;
                        directory_metas.push((path, metadata));
                    }
                    ArchiveEvent::FileStart { metadata, .. } => {
                        let rel = sanitize_relative_path(metadata.filename().as_str())?;
                        let path = root.join(&rel);
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        let f = open_new_file(&path, &rel.to_string_lossy(), force)?;
                        current = Some((f, path, metadata));
                    }
                    ArchiveEvent::FileData(data) => {
                        let (f, _, _) = current.as_mut().ok_or_else(|| {
                            WorkflowError::File("Archive stream out of order".to_string())
                        })?;
                        f.write_all(data.as_slice())?;
                    }
                    ArchiveEvent::FileEnd => {
                        let (f, _, entry_metadata) = current.take().ok_or_else(|| {
                            WorkflowError::File("Archive stream out of order".to_string())
                        })?;
                        apply_metadata(&f, &entry_metadata)?;
                    }
                    ArchiveEvent::End => {}
                }
            }
            Ok(())
        })?;
        parser.finish()?;

        // Restore directory metadata deepest-first: writing children bumps a
        // parent's mtime, so parents must be stamped after their contents.
        directory_metas.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (path, dir_metadata) in &directory_metas {
            apply_path_metadata(path, dir_metadata)?;
        }
        apply_path_metadata(&root, metadata)?;
        Ok(())
    })();

    match result {
        Ok(()) => Ok(DecryptionOutputFile {
            path: root,
            filename: display_name,
        }),
        Err(e) => {
            if let Some((_, path, _)) = current {
                let _ = std::fs::remove_file(path);
            }
            Err(e)
        }
    }
}

/// [`apply_metadata`] for paths without an open handle (directories).
fn apply_path_metadata(path: &Path, metadata: &FileMetadata) -> WorkflowResult<()> {
    let f = std::fs::File::open(path)?;
    apply_metadata(&f, metadata)
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
