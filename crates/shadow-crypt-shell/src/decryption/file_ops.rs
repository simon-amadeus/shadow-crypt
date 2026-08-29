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
    utils::{AtomicOutputFile, read_up_to, sanitize_relative_path},
};

/// Claims `path` for output, enforcing the no-overwrite policy. Returns
/// true when a fresh placeholder file was created. With --force an existing
/// file is left untouched (returns false) and only replaced when
/// [`AtomicOutputFile::commit`] renames the finished content over it, so a
/// failed decryption never destroys what was there before. The rename
/// replaces a symlink at the target rather than following it.
fn claim_output_path(path: &Path, display_name: &str, force: bool) -> WorkflowResult<bool> {
    // create_new makes the no-overwrite check atomic: no window between an
    // exists() check and creation, and symlinks are never followed to clobber
    // an existing target.
    match std::fs::File::create_new(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if force {
                Ok(false)
            } else {
                Err(WorkflowError::File(format!(
                    "Output file '{}' already exists (use --force to overwrite)",
                    display_name
                )))
            }
        }
        Err(e) => Err(WorkflowError::Io(e)),
    }
}

/// Creates the plaintext output for a decrypted filename, enforcing the
/// no-traversal and no-overwrite policies. Multi-component names (from
/// recursive encryption) recreate their directories under `output_dir`.
/// The returned writer is crash-safe: the final path holds an empty
/// placeholder (or, with --force, the pre-existing file) until
/// [`AtomicOutputFile::commit`] renames the finished content over it. The
/// returned bool says whether a placeholder was created and may be removed
/// on failure.
fn create_output_file(
    filename: &SecureString,
    output_dir: &Path,
    force: bool,
) -> WorkflowResult<(AtomicOutputFile, DecryptionOutputFile, bool)> {
    let safe_rel = sanitize_relative_path(filename.as_str())?;
    let path = output_dir.join(&safe_rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let display_name = safe_rel.to_string_lossy().into_owned();
    // Claim the final name (placeholder), then write next to it.
    let claimed = claim_output_path(&path, &display_name, force)?;
    let out = AtomicOutputFile::start(path.clone())?;

    Ok((
        out,
        DecryptionOutputFile {
            path,
            filename: display_name,
        },
        claimed,
    ))
}

/// Restores preserved metadata onto the decrypted file. Applied after the
/// content is written, since writing would bump the mtime again.
fn apply_metadata(f: &std::fs::File, metadata: &FileMetadata) -> WorkflowResult<()> {
    #[cfg(unix)]
    if let Some(mode) = metadata.mode() {
        use std::os::unix::fs::PermissionsExt;
        // The mode comes from (authenticated but sender-controlled)
        // metadata: drop setuid/setgid/sticky so decrypting someone else's
        // file can never plant a privilege-escalation primitive.
        f.set_permissions(std::fs::Permissions::from_mode(mode & 0o777))?;
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
    let (mut out, output_file, claimed) = create_output_file(metadata.filename(), output_dir, force)?;

    let result = (|| -> WorkflowResult<()> {
        let mut decryptor = parsed.content_decryptor(key);
        pump_content(file, parsed, &mut decryptor, |plaintext| {
            out.write_all(plaintext)?;
            Ok(())
        })?;
        apply_metadata(out.as_file(), metadata)?;
        out.commit()?;
        Ok(())
    })();

    match result {
        Ok(()) => Ok(output_file),
        Err(e) => {
            drop(out); // removes the temporary file
            // Only remove the placeholder we created; with --force the
            // final path may still hold the user's pre-existing file.
            if claimed {
                let _ = std::fs::remove_file(&output_file.path);
            }
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

    match root.symlink_metadata() {
        Ok(meta) => {
            if !force {
                return Err(WorkflowError::File(format!(
                    "Output directory '{}' already exists (use --force to extract into it)",
                    display_name
                )));
            }
            // symlink_metadata does not follow symlinks: a link to a
            // directory elsewhere is rejected rather than extracted
            // through, which would write (and force-remove) files outside
            // the output directory.
            if !meta.file_type().is_dir() {
                return Err(WorkflowError::File(format!(
                    "Output path '{}' exists and is not a directory",
                    display_name
                )));
            }
        }
        Err(_) => std::fs::create_dir_all(&root)?,
    }

    let mut parser = ArchiveParser::new();
    // (atomic writer, on-disk path, entry metadata, placeholder claimed) of
    // the file being written.
    let mut current: Option<(AtomicOutputFile, PathBuf, FileMetadata, bool)> = None;
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
                        // Claim the final name, then write crash-safely next
                        // to it.
                        let claimed = claim_output_path(&path, &rel.to_string_lossy(), force)?;
                        let out = AtomicOutputFile::start(path.clone())?;
                        current = Some((out, path, metadata, claimed));
                    }
                    ArchiveEvent::FileData(data) => {
                        let (out, _, _, _) = current.as_mut().ok_or_else(|| {
                            WorkflowError::File("Archive stream out of order".to_string())
                        })?;
                        out.write_all(data.as_slice())?;
                    }
                    ArchiveEvent::FileEnd => {
                        let (mut out, _, entry_metadata, _) = current.take().ok_or_else(|| {
                            WorkflowError::File("Archive stream out of order".to_string())
                        })?;
                        apply_metadata(out.as_file(), &entry_metadata)?;
                        out.commit()?;
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
            // Only remove the placeholder we created; with --force the
            // final path may still hold the user's pre-existing file.
            if let Some((out, path, _, claimed)) = current {
                drop(out); // removes the temporary file
                if claimed {
                    let _ = std::fs::remove_file(path);
                }
            }
            Err(e)
        }
    }
}

/// [`apply_metadata`] for paths without an open handle (directories).
fn apply_path_metadata(path: &Path, metadata: &FileMetadata) -> WorkflowResult<()> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // Windows can only open directories with FILE_FLAG_BACKUP_SEMANTICS,
    // and setting the mtime needs write access to the handle.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.write(true).custom_flags(0x0200_0000); // FILE_FLAG_BACKUP_SEMANTICS
    }
    let f = options.open(path)?;
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
        let (mut f, output_file, _) = create_output_file(&filename, output_dir, force)?;
        f.write_all(content.as_slice())?;
        f.commit()?;
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
    fn test_force_keeps_existing_file_when_not_committed() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let output_path = temp_dir.path().join("test.txt");
        fs::write(&output_path, b"precious").unwrap();

        let filename = SecureString::new("test.txt".to_string());
        let (mut f, _, claimed) = create_output_file(&filename, temp_dir.path(), true).unwrap();
        assert!(!claimed, "existing file must not be claimed as a placeholder");
        f.write_all(b"partial").unwrap();
        drop(f); // simulated failure: dropped without commit

        // A failed forced decryption must leave the pre-existing file intact.
        assert_eq!(fs::read(&output_path).unwrap(), b"precious");
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
