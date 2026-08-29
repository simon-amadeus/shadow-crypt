use std::{
    io::{BufWriter, Write},
    path::PathBuf,
};

use rand::rand_core::{OsRng, TryRngCore};
use shadow_crypt_core::{
    file::FileMetadata,
    memory::SecureString,
    v3::{header::FileHeader, stream::StreamSealer},
};

use crate::{
    encryption::file::{EncryptionInputFile, EncryptionOutputFile},
    errors::{WorkflowError, WorkflowResult},
    utils::read_up_to,
};

/// Collects the metadata to preserve for an input file. Fields that cannot
/// be read (or do not exist on this platform) are simply absent.
pub fn gather_metadata(file: &EncryptionInputFile) -> FileMetadata {
    let fs_metadata = std::fs::metadata(&file.path).ok();
    let mtime = fs_metadata.as_ref().and_then(|m| m.modified().ok());

    #[cfg(unix)]
    let mode = fs_metadata.as_ref().map(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o7777
    });
    #[cfg(not(unix))]
    let mode = None;

    FileMetadata::new(SecureString::new(file.filename.clone()), mtime, mode)
}

/// Streams the input file through the sealer into a fresh output file:
/// header first, then one encrypted chunk at a time, with memory bounded by
/// the chunk size. A partially written output is removed on failure.
pub fn stream_encrypt_file(
    file: &EncryptionInputFile,
    header: &FileHeader,
    mut sealer: StreamSealer,
    output_dir: &std::path::Path,
) -> WorkflowResult<EncryptionOutputFile> {
    let (out, output_file) = create_encryption_output_file(output_dir)?;

    let result = (|| -> WorkflowResult<()> {
        let mut writer = BufWriter::new(out);
        writer.write_all(&header.serialize())?;

        let mut reader = std::fs::File::open(&file.path)?;
        let chunk_size = sealer.chunk_plaintext_len();
        let mut current = vec![0u8; chunk_size];
        let mut next = vec![0u8; chunk_size];

        // Double-buffered read: a chunk is final when the read after it
        // returns nothing, so exact-multiple files end on a full final chunk
        // and empty files produce one empty final chunk.
        let mut current_len = read_up_to(&mut reader, &mut current)?;
        loop {
            let next_len = read_up_to(&mut reader, &mut next)?;
            let is_last = next_len == 0;
            writer.write_all(&sealer.seal_chunk(&current[..current_len], is_last)?)?;
            if is_last {
                break;
            }
            std::mem::swap(&mut current, &mut next);
            current_len = next_len;
        }

        writer.flush()?;
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

fn generate_output_filename() -> WorkflowResult<String> {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const NAME_LENGTH: usize = 16;
    // Largest multiple of CHARSET.len() that fits in a byte; rejection
    // sampling below this bound keeps every character equally likely.
    const REJECTION_BOUND: u8 = (u8::MAX / CHARSET.len() as u8) * CHARSET.len() as u8;

    let mut name = String::with_capacity(NAME_LENGTH);
    let mut bytes = [0u8; 2 * NAME_LENGTH];
    while name.len() < NAME_LENGTH {
        OsRng.try_fill_bytes(&mut bytes).map_err(|e| {
            WorkflowError::File(format!("Failed to generate output filename: {}", e))
        })?;
        for byte in bytes {
            if byte < REJECTION_BOUND && name.len() < NAME_LENGTH {
                name.push(CHARSET[byte as usize % CHARSET.len()] as char);
            }
        }
    }
    Ok(name)
}

fn create_encryption_output_file(
    output_dir: &std::path::Path,
) -> WorkflowResult<(std::fs::File, EncryptionOutputFile)> {
    // create_new claims the filename atomically, so concurrent encryptions
    // can never race each other (or an attacker) into overwriting a file.
    for _ in 0..1000 {
        let mut path = PathBuf::from(generate_output_filename()?);
        path.set_extension("shadow");

        let full_path = output_dir.join(&path);

        match std::fs::File::create_new(&full_path) {
            Ok(f) => {
                let filename_str = path
                    .to_str()
                    .ok_or_else(|| WorkflowError::File("Invalid output filename".to_string()))?
                    .to_string();

                return Ok((
                    f,
                    EncryptionOutputFile {
                        path: full_path,
                        filename: filename_str,
                    },
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Err(WorkflowError::File(
        "Unable to generate a unique output filename after 1000 attempts".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_crypt_core::{
        memory::SecureKey, v3::file::EncryptedFile, v3::key::KeyDerivationParams,
    };
    use std::fs;
    use tempfile::TempDir;

    fn input_file(dir: &std::path::Path, name: &str, content: &[u8]) -> EncryptionInputFile {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        EncryptionInputFile {
            path,
            filename: name.to_string(),
            size: content.len() as u64,
        }
    }

    #[test]
    fn test_generate_output_filename() {
        let filename = generate_output_filename().unwrap();
        assert_eq!(filename.len(), 16);
        assert!(filename.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn test_create_encryption_output_file() {
        let temp_dir = TempDir::new().unwrap();

        let (_, first) = create_encryption_output_file(temp_dir.path()).unwrap();
        let (_, second) = create_encryption_output_file(temp_dir.path()).unwrap();

        assert!(first.path.exists());
        assert!(second.path.exists());
        assert_ne!(first.filename, second.filename);
        assert!(first.filename.ends_with(".shadow"));
    }

    #[test]
    fn test_gather_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let file = input_file(temp_dir.path(), "meta.txt", b"content");

        let metadata = gather_metadata(&file);
        assert_eq!(metadata.filename().as_str(), "meta.txt");
        assert!(metadata.mtime().is_some());
        #[cfg(unix)]
        assert!(metadata.mode().is_some());
    }

    #[test]
    fn test_stream_encrypt_file_round_trips() {
        let temp_dir = TempDir::new().unwrap();
        let content = b"stream me please".repeat(10);
        let file = input_file(temp_dir.path(), "in.txt", &content);

        let key = SecureKey::new([7u8; 32]);
        let params = KeyDerivationParams::test_defaults();
        let (header, sealer) = StreamSealer::begin(
            &gather_metadata(&file),
            &key,
            params,
            [1u8; 16],
            [2u8; 16],
            [3u8; 24],
        )
        .unwrap();

        let output_file = stream_encrypt_file(&file, &header, sealer, temp_dir.path()).unwrap();
        assert!(output_file.path.exists());
        assert!(output_file.filename.ends_with(".shadow"));

        // The written file must decrypt back to the original content.
        let bytes = fs::read(&output_file.path).unwrap();
        let decrypted = EncryptedFile::from_bytes(&bytes)
            .unwrap()
            .decrypt(&key)
            .unwrap();
        assert_eq!(decrypted.filename().as_str(), "in.txt");
        assert_eq!(decrypted.content().as_slice(), content.as_slice());
    }

    #[test]
    fn test_stream_encrypt_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let file = input_file(temp_dir.path(), "empty.txt", b"");

        let key = SecureKey::new([7u8; 32]);
        let (header, sealer) = StreamSealer::begin(
            &gather_metadata(&file),
            &key,
            KeyDerivationParams::test_defaults(),
            [1u8; 16],
            [2u8; 16],
            [3u8; 24],
        )
        .unwrap();

        let output_file = stream_encrypt_file(&file, &header, sealer, temp_dir.path()).unwrap();
        let bytes = fs::read(&output_file.path).unwrap();
        let decrypted = EncryptedFile::from_bytes(&bytes)
            .unwrap()
            .decrypt(&key)
            .unwrap();
        assert!(decrypted.content().as_slice().is_empty());
    }

    #[test]
    fn test_stream_encrypt_missing_input_cleans_up_output() {
        let temp_dir = TempDir::new().unwrap();
        let file = EncryptionInputFile {
            path: temp_dir.path().join("missing.txt"),
            filename: "missing.txt".to_string(),
            size: 0,
        };

        let key = SecureKey::new([7u8; 32]);
        let (header, sealer) = StreamSealer::begin(
            &gather_metadata(&file),
            &key,
            KeyDerivationParams::test_defaults(),
            [1u8; 16],
            [2u8; 16],
            [3u8; 24],
        )
        .unwrap();

        assert!(stream_encrypt_file(&file, &header, sealer, temp_dir.path()).is_err());
        // No orphaned partial .shadow file may remain.
        let leftovers: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "shadow"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
