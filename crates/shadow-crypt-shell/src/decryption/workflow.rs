use rayon::prelude::*;
use shadow_crypt_core::{
    algorithm::Algorithm,
    memory::{SecureBytes, SecureString},
    progress::ProgressCounter,
    report::DecryptionReport,
    v1, v2,
    version::{Version, read_file_version},
};

use crate::{
    decryption::{
        file::{DecryptionInput, DecryptionInputFile, DecryptionOutputFile},
        file_ops::{load_file_bytes, store_plaintext_file},
    },
    errors::{WorkflowError, WorkflowResult},
    kdf::derive_key_from_untrusted_params,
    ui::{display_decryption_report, display_progress},
    utils::parse_string_from_bytes,
};

pub fn run_workflow(input: DecryptionInput) -> WorkflowResult<()> {
    let total = input.files.len();
    let counter = ProgressCounter::new(total as u64);

    // Process files in parallel using rayon
    let failures: usize = input
        .files
        .par_iter()
        .map(|input_file| {
            let result =
                process_file_decryption(input_file.to_owned(), &input.password, &input.output_dir);
            counter.increment();
            display_progress(&counter);
            let failed = result.is_err();
            display_decryption_report(result);
            usize::from(failed)
        })
        .sum();

    if failures > 0 {
        return Err(WorkflowError::Decryption(format!(
            "{} of {} file(s) failed to decrypt",
            failures, total
        )));
    }

    Ok(())
}

fn process_file_decryption(
    file: DecryptionInputFile,
    password: &SecureString,
    output_dir: &std::path::Path,
) -> WorkflowResult<DecryptionReport> {
    let start_time = std::time::Instant::now();

    let bytes = load_file_bytes(&file)?;

    // Dispatch on the version byte; each format version is decrypted by its
    // own self-contained code path.
    let (filename, content, algorithm) = match read_file_version(&bytes)? {
        Version::V1 => decrypt_v1(&bytes, password)?,
        Version::V2 => decrypt_v2(&bytes, password)?,
    };

    let output_file: DecryptionOutputFile = store_plaintext_file(&filename, &content, output_dir)?;

    let duration = start_time.elapsed();

    Ok(DecryptionReport::new(
        file.filename,
        output_file.filename,
        duration,
        algorithm,
    ))
}

fn decrypt_v1(
    bytes: &[u8],
    password: &SecureString,
) -> WorkflowResult<(SecureString, SecureBytes, Algorithm)> {
    let encrypted_file = v1::file_ops::get_encrypted_file_from_bytes(bytes)?;
    let header = encrypted_file.header();

    let kdf_params = v1::header_ops::get_kdf_params(header);
    let key = derive_key_from_untrusted_params(
        kdf_params.memory_cost,
        kdf_params.time_cost,
        kdf_params.parallelism,
        kdf_params.key_size,
        || v1::key_ops::derive_key(password.as_str().as_bytes(), &header.salt, &kdf_params),
    )?;

    let (filename_bytes, algorithm) = v1::crypt::decrypt_bytes(
        &header.filename_ciphertext,
        key.as_bytes(),
        &header.filename_nonce,
    )?;
    let filename = parse_string_from_bytes(&filename_bytes)?;

    let (content, _) = v1::crypt::decrypt_bytes(
        encrypted_file.ciphertext(),
        key.as_bytes(),
        &header.content_nonce,
    )?;

    Ok((filename, content, algorithm))
}

fn decrypt_v2(
    bytes: &[u8],
    password: &SecureString,
) -> WorkflowResult<(SecureString, SecureBytes, Algorithm)> {
    let encrypted_file = v2::file_ops::get_encrypted_file_from_bytes(bytes)?;
    let header = encrypted_file.header();

    let kdf_params = v2::header_ops::get_kdf_params(header);
    let key = derive_key_from_untrusted_params(
        kdf_params.memory_cost,
        kdf_params.time_cost,
        kdf_params.parallelism,
        kdf_params.key_size,
        || v2::key_ops::derive_key(password.as_str().as_bytes(), &header.salt, &kdf_params),
    )?;

    // v2 authenticates the header fields as associated data, with separate
    // domains for filename and content.
    let binding = header.binding();

    let (filename_bytes, algorithm) = v2::crypt::decrypt_bytes(
        &header.filename_ciphertext,
        key.as_bytes(),
        &header.filename_nonce,
        &binding.aad(v2::header::AadPurpose::Filename),
    )?;
    let filename = parse_string_from_bytes(&filename_bytes)?;

    let (content, _) = v2::crypt::decrypt_bytes(
        encrypted_file.ciphertext(),
        key.as_bytes(),
        &header.content_nonce,
        &binding.aad(v2::header::AadPurpose::Content),
    )?;

    Ok((filename, content, algorithm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MAX_KDF_MEMORY_KIB;
    use shadow_crypt_core::profile::SecurityProfile;

    #[test]
    fn test_v1_oversized_kdf_params_rejected_before_derivation() {
        // A crafted v1 file claiming huge KDF costs must be rejected before
        // any derivation is attempted.
        let kdf_params = v1::key::KeyDerivationParams::new(MAX_KDF_MEMORY_KIB + 1, 1, 1, 32);
        let header =
            v1::header::FileHeader::new([0u8; 16], kdf_params, [0u8; 24], [0u8; 24], vec![1, 2, 3]);
        let mut bytes = v1::header_ops::serialize(&header);
        bytes.extend_from_slice(b"ciphertext");

        let password = SecureString::new("pw".to_string());
        assert!(decrypt_v1(&bytes, &password).is_err());
    }

    #[test]
    fn test_v2_oversized_kdf_params_rejected_before_derivation() {
        let kdf_params = v2::key::KeyDerivationParams::new(u32::MAX, 1, 1, 32);
        let header =
            v2::header::FileHeader::new([0u8; 16], kdf_params, [0u8; 24], [0u8; 24], vec![1, 2, 3])
                .unwrap();
        let mut bytes = v2::header_ops::serialize(&header);
        bytes.extend_from_slice(b"ciphertext");

        let password = SecureString::new("pw".to_string());
        assert!(decrypt_v2(&bytes, &password).is_err());
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

        let (key, _) =
            v2::key_ops::derive_key(password.as_str().as_bytes(), &salt, &kdf_params).unwrap();
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
        let mut bytes = v2::header_ops::serialize(&swapped_header);
        bytes.extend_from_slice(&filename_ct);

        assert!(decrypt_v2(&bytes, &password).is_err());
    }

    #[test]
    fn test_v2_round_trip_via_raw_bytes() {
        let password = SecureString::new("testpassword".to_string());
        let salt = [1u8; 16];
        let kdf_params = v2::key::KeyDerivationParams::from(SecurityProfile::Test);
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];

        let (key, _) =
            v2::key_ops::derive_key(password.as_str().as_bytes(), &salt, &kdf_params).unwrap();
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

        let header = v2::header::FileHeader::new(
            salt,
            kdf_params,
            content_nonce,
            filename_nonce,
            filename_ct,
        )
        .unwrap();
        let mut bytes = v2::header_ops::serialize(&header);
        bytes.extend_from_slice(&content_ct);

        let (filename, content, _) = decrypt_v2(&bytes, &password).unwrap();
        assert_eq!(filename.as_str(), "name.txt");
        assert_eq!(content.as_slice(), b"content");
    }
}
