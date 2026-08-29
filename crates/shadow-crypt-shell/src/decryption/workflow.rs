use rayon::prelude::*;
use shadow_crypt_core::{
    memory::SecureString,
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
    let (output_file, algorithm): (DecryptionOutputFile, _) = match read_file_version(&bytes)? {
        Version::V1 => {
            let plaintext = decrypt_v1(&bytes, password)?;
            (
                store_plaintext_file(plaintext.filename(), plaintext.content(), output_dir)?,
                shadow_crypt_core::algorithm::Algorithm::XChaCha20Poly1305,
            )
        }
        Version::V2 => {
            let plaintext = decrypt_v2(&bytes, password)?;
            (
                store_plaintext_file(plaintext.filename(), plaintext.content(), output_dir)?,
                v2::ALGORITHM,
            )
        }
    };

    let duration = start_time.elapsed();

    Ok(DecryptionReport::new(
        file.filename,
        output_file.filename,
        duration,
        algorithm,
    ))
}

fn decrypt_v1(bytes: &[u8], password: &SecureString) -> WorkflowResult<v1::file::PlaintextFile> {
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

    let (filename_bytes, _) = v1::crypt::decrypt_bytes(
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

    Ok(v1::file::PlaintextFile::new(filename, content))
}

fn decrypt_v2(bytes: &[u8], password: &SecureString) -> WorkflowResult<v2::file::PlaintextFile> {
    let encrypted_file = v2::file::EncryptedFile::from_bytes(bytes)?;
    let kdf_params = encrypted_file.header().kdf_params();

    let key = derive_key_from_untrusted_params(
        kdf_params.memory_cost,
        kdf_params.time_cost,
        kdf_params.parallelism,
        kdf_params.key_size,
        || kdf_params.derive_key(password.as_str().as_bytes(), &encrypted_file.header().salt),
    )?;

    Ok(encrypted_file.decrypt(&key)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MAX_KDF_MEMORY_KIB;
    use shadow_crypt_core::{
        memory::{SecureBytes, SecureString},
        profile::SecurityProfile,
    };

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
        let mut bytes = header.serialize();
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

        assert!(decrypt_v2(&bytes, &password).is_err());
    }

    #[test]
    fn test_v2_round_trip_via_raw_bytes() {
        let password = SecureString::new("testpassword".to_string());
        let salt = [1u8; 16];
        let kdf_params = v2::key::KeyDerivationParams::from(SecurityProfile::Test);

        let (key, _) = kdf_params
            .derive_key(password.as_str().as_bytes(), &salt)
            .unwrap();

        let plaintext_file = v2::file::PlaintextFile::new(
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

        let decrypted = decrypt_v2(&sealed.to_bytes(), &password).unwrap();
        assert_eq!(decrypted.filename().as_str(), "name.txt");
        assert_eq!(decrypted.content().as_slice(), b"content");
    }
}
