use rayon::prelude::*;
use shadow_crypt_core::{
    memory::SecureString,
    progress::ProgressCounter,
    report::DecryptionReport,
    vault::{MAX_HEADER_LEN, ParsedFile},
};

use crate::{
    decryption::{
        file::{DecryptionInput, DecryptionInputFile},
        file_ops::stream_decrypt_file,
    },
    errors::{WorkflowError, WorkflowResult},
    kdf::derive_untrusted_key,
    ui::{display_decryption_success, display_error, display_progress},
    utils::read_n_bytes_from_file,
};

pub fn run_workflow(input: DecryptionInput) -> WorkflowResult<()> {
    let total = input.files.len();
    let counter = ProgressCounter::new(total as u64);

    // Process files in parallel using rayon
    let failures: Vec<WorkflowError> = input
        .files
        .par_iter()
        .filter_map(|input_file| {
            let result = process_file_decryption(
                input_file.to_owned(),
                &input.password,
                &input.output_dir,
                input.force,
            )
            .map_err(|e| WorkflowError::per_file(&input_file.filename, e));
            counter.increment();
            if !input.quiet {
                display_progress(&counter);
            }
            match result {
                Ok(report) => {
                    if !input.quiet {
                        display_decryption_success(&report);
                    }
                    None
                }
                Err(e) => {
                    display_error(&e);
                    Some(e)
                }
            }
        })
        .collect();

    if !failures.is_empty() {
        let message = format!("{} of {} file(s) failed to decrypt", failures.len(), total);
        // Distinguish "everything failed to authenticate" (wrong password /
        // corruption) so scripts get a dedicated exit code.
        return Err(if failures.iter().all(|e| e.is_authentication_failure()) {
            WorkflowError::Authentication(message)
        } else {
            WorkflowError::Decryption(message)
        });
    }

    Ok(())
}

fn process_file_decryption(
    file: DecryptionInputFile,
    password: &SecureString,
    output_dir: &std::path::Path,
    force: bool,
) -> WorkflowResult<DecryptionReport> {
    let start_time = std::time::Instant::now();

    // Only the header is read up front; the content is streamed afterwards,
    // so memory stays bounded regardless of file size. ParsedFile dispatches
    // to the file's own format version internally; this workflow is
    // version-agnostic.
    let header_bytes = read_n_bytes_from_file(&file.path, MAX_HEADER_LEN)?;
    let parsed = ParsedFile::parse(header_bytes.as_slice())?;
    let key = derive_untrusted_key(&parsed, password)?;

    // Decrypting the metadata also verifies the password before any output
    // file is created.
    let metadata = parsed.decrypt_metadata(&key)?;
    let output_file = stream_decrypt_file(&file, &parsed, &key, &metadata, output_dir, force)?;

    let duration = start_time.elapsed();

    Ok(DecryptionReport::new(
        file.filename,
        output_file.filename,
        duration,
        parsed.algorithm(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MAX_KDF_MEMORY_KIB;
    use shadow_crypt_core::{
        file::PlaintextFile,
        memory::{SecureBytes, SecureString},
        profile::SecurityProfile,
        v1, v2,
    };

    /// The parse → guarded derive → decrypt chain exactly as the workflow
    /// runs it.
    fn decrypt(bytes: &[u8], password: &SecureString) -> WorkflowResult<PlaintextFile> {
        let parsed = ParsedFile::parse(bytes)?;
        let key = derive_untrusted_key(&parsed, password)?;
        Ok(parsed.decrypt(&key)?)
    }

    #[test]
    fn test_v1_oversized_kdf_params_rejected_before_derivation() {
        // A crafted v1 file claiming huge KDF costs must be rejected before
        // any derivation is attempted.
        let kdf_params = v1::key::KeyDerivationParams::new(MAX_KDF_MEMORY_KIB + 1, 1, 1, 32);
        let header =
            v1::header::FileHeader::new([0u8; 16], kdf_params, [0u8; 24], [0u8; 24], vec![1, 2, 3]);
        let mut bytes = header.serialize();
        bytes.extend_from_slice(b"ciphertext");

        let password = SecureString::new("pw".to_string());
        assert!(decrypt(&bytes, &password).is_err());
    }

    #[test]
    fn test_v2_oversized_kdf_params_rejected_before_derivation() {
        let kdf_params = v2::key::KeyDerivationParams::new(u32::MAX, 1, 1, 32);
        let header =
            v2::header::FileHeader::new([0u8; 16], kdf_params, [0u8; 24], [0u8; 24], vec![1, 2, 3])
                .unwrap();
        let mut bytes = header.serialize();
        bytes.extend_from_slice(b"ciphertext");

        let password = SecureString::new("pw".to_string());
        assert!(decrypt(&bytes, &password).is_err());
    }

    #[test]
    fn test_v2_swapped_ciphertext_pairs_fail_decryption() {
        // End-to-end version of the swap attack: encrypt filename + content
        // under one key, then build a file whose filename slot holds the
        // content pair and vice versa. v2 must refuse to decrypt it.
        let password = SecureString::new("testpassword".to_string());
        let salt = [1u8; 16];
        let kdf_params = v2::key::KeyDerivationParams::from(SecurityProfile::Test);
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];

        let (key, _) = kdf_params
            .derive_key(password.as_str().as_bytes(), &salt)
            .unwrap();
        let binding =
            v2::header::HeaderBinding::new(&salt, &kdf_params, &content_nonce, &filename_nonce);

        let (filename_ct, _) = v2::crypt::encrypt_bytes(
            b"name.txt",
            key.as_bytes(),
            &filename_nonce,
            &binding.aad(v2::header::AadPurpose::Filename),
        )
        .unwrap();
        let (content_ct, _) = v2::crypt::encrypt_bytes(
            b"content",
            key.as_bytes(),
            &content_nonce,
            &binding.aad(v2::header::AadPurpose::Content),
        )
        .unwrap();

        // Swap: content pair goes into the filename slot, filename pair
        // becomes the content. Nonces swap along with the ciphertexts, which
        // is exactly what made this pass undetected in v1.
        let swapped_header = v2::header::FileHeader::new(
            salt,
            kdf_params,
            filename_nonce, // content slot now uses the filename nonce
            content_nonce,  // filename slot now uses the content nonce
            content_ct,     // filename slot holds the content ciphertext
        )
        .unwrap();
        let mut bytes = swapped_header.serialize();
        bytes.extend_from_slice(&filename_ct);

        assert!(decrypt(&bytes, &password).is_err());
    }

    #[test]
    fn test_v2_round_trip_via_raw_bytes() {
        let password = SecureString::new("testpassword".to_string());
        let salt = [1u8; 16];
        let kdf_params = v2::key::KeyDerivationParams::from(SecurityProfile::Test);

        let (key, _) = kdf_params
            .derive_key(password.as_str().as_bytes(), &salt)
            .unwrap();

        let plaintext_file = PlaintextFile::new(
            SecureString::new("name.txt".to_string()),
            SecureBytes::new(b"content".to_vec()),
        );
        let sealed = v2::file::EncryptedFile::seal(
            &plaintext_file,
            &key,
            kdf_params,
            salt,
            [2u8; 24],
            [3u8; 24],
        )
        .unwrap();

        let decrypted = decrypt(&sealed.to_bytes(), &password).unwrap();
        assert_eq!(decrypted.filename().as_str(), "name.txt");
        assert_eq!(decrypted.content().as_slice(), b"content");
    }
}
