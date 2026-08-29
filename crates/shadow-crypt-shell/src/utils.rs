use std::io::{Read, Write};

use shadow_crypt_core::memory::SecureBytes;

use crate::errors::{WorkflowError, WorkflowResult};

pub fn read_n_bytes_from_file(path: &std::path::Path, n: usize) -> WorkflowResult<SecureBytes> {
    let f = std::fs::File::open(path)?;
    let mut buffer = Vec::new();
    f.take(n as u64).read_to_end(&mut buffer)?;

    Ok(SecureBytes::new(buffer))
}

/// Sanitizes a '/'-separated path from decrypted metadata into a relative
/// path that cannot escape the output directory: rejects `..` components,
/// backslashes, and (on Windows) drive prefixes and `:` stream separators,
/// drops empty and `.` components (which also relativizes
/// absolute paths). The decrypted name is deliberately not echoed into
/// error messages.
pub fn sanitize_relative_path(name: &str) -> WorkflowResult<std::path::PathBuf> {
    if name.contains('\\') {
        return Err(WorkflowError::File(
            "Decrypted path contains unsupported separators".to_string(),
        ));
    }
    let mut out = std::path::PathBuf::new();
    for component in name.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                return Err(WorkflowError::File(
                    "Decrypted path contains unsafe components".to_string(),
                ));
            }
            component => {
                // On Windows, ':' forms drive prefixes ("C:evil" makes
                // Path::push discard everything accumulated so far) and NTFS
                // alternate data streams.
                if cfg!(windows) && component.contains(':') {
                    return Err(WorkflowError::File(
                        "Decrypted path contains unsafe components".to_string(),
                    ));
                }
                out.push(component);
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(WorkflowError::File(
            "Decrypted path contains no usable components".to_string(),
        ));
    }
    // Belt and braces: anything the platform parses as a prefix, root, or
    // dot component would let output_dir.join(out) escape the output
    // directory.
    if !out
        .components()
        .all(|c| matches!(c, std::path::Component::Normal(_)))
    {
        return Err(WorkflowError::File(
            "Decrypted path contains unsafe components".to_string(),
        ));
    }
    Ok(out)
}

/// Reads from `reader` until `buf` is full or EOF; returns the bytes read.
/// Unlike a bare `read` call this only returns short on EOF, which the
/// streaming loops rely on to spot the final chunk.
pub fn read_up_to(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Crash-safe output writing: content goes to a hidden temporary file next
/// to `final_path`, and [`AtomicOutputFile::commit`] fsyncs it and renames
/// it into place. Until then the final path holds whatever the caller put
/// there (typically an empty placeholder claiming the name), so a crash or
/// error never leaves a truncated file that looks complete. Dropping
/// without committing removes the temporary file.
///
/// A hard crash (kill, power loss) can still leave the empty placeholder
/// and a `.<name>.tmpN` file behind; both are inert and safe to delete
/// manually. We deliberately never auto-clean them: deleting files we
/// cannot prove we created is worse than the litter.
pub struct AtomicOutputFile {
    tmp_path: std::path::PathBuf,
    final_path: std::path::PathBuf,
    file: Option<std::fs::File>,
}

impl AtomicOutputFile {
    /// Starts writing for `final_path`, which the caller must already have
    /// claimed (created) so the name is reserved under its own overwrite
    /// policy.
    pub fn start(final_path: std::path::PathBuf) -> WorkflowResult<Self> {
        let file_name = final_path
            .file_name()
            .ok_or_else(|| WorkflowError::File("Output path has no filename".to_string()))?
            .to_string_lossy()
            .into_owned();

        for n in 0..1000u32 {
            let tmp_path = final_path.with_file_name(format!(".{file_name}.tmp{n}"));
            match std::fs::File::create_new(&tmp_path) {
                Ok(file) => {
                    return Ok(Self {
                        tmp_path,
                        final_path,
                        file: Some(file),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(WorkflowError::File(
            "Unable to create a temporary output file".to_string(),
        ))
    }

    /// The temporary file being written, e.g. to apply metadata before
    /// committing (rename preserves it).
    pub fn as_file(&self) -> &std::fs::File {
        self.file.as_ref().expect("not committed")
    }

    /// Flushes the content to disk and atomically renames it over the final
    /// path (replacing the caller's placeholder).
    pub fn commit(&mut self) -> WorkflowResult<()> {
        let file = self
            .file
            .take()
            .ok_or_else(|| WorkflowError::File("Output already committed".to_string()))?;
        file.sync_all()?;
        drop(file);

        // On Windows, rename does not replace an existing destination.
        #[cfg(windows)]
        {
            let _ = std::fs::remove_file(&self.final_path);
        }
        std::fs::rename(&self.tmp_path, &self.final_path)?;

        // Best-effort directory sync so the rename itself is durable.
        #[cfg(unix)]
        if let Some(dir) = self.final_path.parent()
            && let Ok(dir_handle) = std::fs::File::open(dir)
        {
            let _ = dir_handle.sync_all();
        }
        Ok(())
    }
}

impl Write for AtomicOutputFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.as_ref().expect("not committed").write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.as_ref().expect("not committed").flush()
    }
}

impl Drop for AtomicOutputFile {
    fn drop(&mut self) {
        if self.file.is_some() {
            self.file = None;
            let _ = std::fs::remove_file(&self.tmp_path);
        }
    }
}

/// Resolves the output directory for a workflow: the given path (created if
/// missing) or the current directory.
pub fn resolve_output_dir(
    output_dir: Option<std::path::PathBuf>,
) -> WorkflowResult<std::path::PathBuf> {
    match output_dir {
        Some(dir) => {
            std::fs::create_dir_all(&dir)?;
            Ok(dir)
        }
        None => Ok(std::env::current_dir()?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::WorkflowError;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_n_bytes_from_file_exact() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"hello world";
        temp_file.write_all(data).unwrap();
        let path = temp_file.path();

        let result = read_n_bytes_from_file(path, 11).unwrap();
        assert_eq!(result.as_slice(), data);
    }

    #[test]
    fn test_read_n_bytes_from_file_more_than_available() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"hello";
        temp_file.write_all(data).unwrap();
        let path = temp_file.path();

        let result = read_n_bytes_from_file(path, 10).unwrap();
        assert_eq!(result.as_slice(), data);
    }

    #[test]
    fn test_read_n_bytes_from_file_less_than_requested() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"hello world this is a test";
        temp_file.write_all(data).unwrap();
        let path = temp_file.path();

        let result = read_n_bytes_from_file(path, 5).unwrap();
        assert_eq!(result.as_slice(), b"hello");
    }

    #[test]
    fn test_read_n_bytes_from_file_zero() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"hello";
        temp_file.write_all(data).unwrap();
        let path = temp_file.path();

        let result = read_n_bytes_from_file(path, 0).unwrap();
        assert_eq!(result.as_slice(), b"");
    }

    #[test]
    fn test_read_n_bytes_from_file_nonexistent() {
        let path = std::path::Path::new("/nonexistent/file");
        let result = read_n_bytes_from_file(path, 10);
        assert!(result.is_err());
        // Should be Io error
        assert!(matches!(result, Err(WorkflowError::Io(_))));
    }

    #[test]
    fn test_sanitize_relative_path() {
        use std::path::PathBuf;

        assert_eq!(
            sanitize_relative_path("a/b/c.txt").unwrap(),
            PathBuf::from("a/b/c.txt")
        );
        assert_eq!(
            sanitize_relative_path("plain.txt").unwrap(),
            PathBuf::from("plain.txt")
        );
        // Absolute and dot components are relativized/dropped.
        assert_eq!(
            sanitize_relative_path("/abs/path").unwrap(),
            PathBuf::from("abs/path")
        );
        assert_eq!(
            sanitize_relative_path("./a//b/.").unwrap(),
            PathBuf::from("a/b")
        );
        // Escapes and unsupported separators are rejected outright.
        for evil in ["..", "../x", "a/../b", "a/..", "a\\b", "", ".", "//"] {
            assert!(sanitize_relative_path(evil).is_err(), "accepted {evil:?}");
        }
        // Drive prefixes and stream separators escape only on Windows;
        // on Unix a ':' is an ordinary filename character.
        #[cfg(windows)]
        for evil in ["C:evil", "C:/evil", "a/C:evil", "file:stream"] {
            assert!(sanitize_relative_path(evil).is_err(), "accepted {evil:?}");
        }
    }

    #[test]
    fn test_resolve_output_dir_creates_missing_directory() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let nested = temp_dir.path().join("a").join("b");

        let resolved = resolve_output_dir(Some(nested.clone())).unwrap();
        assert_eq!(resolved, nested);
        assert!(nested.is_dir());
    }

    #[test]
    fn test_resolve_output_dir_defaults_to_current_dir() {
        let resolved = resolve_output_dir(None).unwrap();
        assert_eq!(resolved, std::env::current_dir().unwrap());
    }

    #[test]
    fn test_atomic_output_file_commit() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let final_path = temp_dir.path().join("out.txt");
        std::fs::write(&final_path, b"").unwrap(); // placeholder claim

        let mut atomic = AtomicOutputFile::start(final_path.clone()).unwrap();
        atomic.write_all(b"content").unwrap();
        atomic.commit().unwrap();
        drop(atomic);

        assert_eq!(std::fs::read(&final_path).unwrap(), b"content");
        // No temporary files remain.
        let leftovers = std::fs::read_dir(temp_dir.path()).unwrap().count();
        assert_eq!(leftovers, 1);
    }

    #[test]
    fn test_atomic_output_file_drop_without_commit_keeps_placeholder() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let final_path = temp_dir.path().join("out.txt");
        std::fs::write(&final_path, b"placeholder").unwrap();

        {
            let mut atomic = AtomicOutputFile::start(final_path.clone()).unwrap();
            atomic.write_all(b"partial").unwrap();
            // dropped without commit
        }

        assert_eq!(std::fs::read(&final_path).unwrap(), b"placeholder");
        let leftovers = std::fs::read_dir(temp_dir.path()).unwrap().count();
        assert_eq!(leftovers, 1, "temporary file must be cleaned up");
    }
}
