use std::sync::Arc;

use rayon::prelude::*;
use shadow_crypt_core::{
    memory::{SecureBytes, SecureKey, SecureString},
    v1::{
        crypt::decrypt_bytes, header::FileHeader, header_ops::get_kdf_params,
        key::KeyDerivationParams, key_ops::derive_key,
    },
};

use crate::{
    errors::WorkflowResult,
    kdf::{validate_untrusted_kdf_params, with_kdf_memory_permit},
    listing::{
        file::{FileInfoList, ListingInput, ShadowFile, ShadowFileInfo},
        file_ops::{load_file_header, scan_directory_for_shadow_files},
    },
    ui,
    utils::parse_string_from_bytes,
};

pub fn run_workflow(input: ListingInput) -> WorkflowResult<()> {
    let shadow_files: Vec<ShadowFile> = scan_directory_for_shadow_files(&input.work_dir)?;
    let password = Arc::new(input.password);

    // Process files in parallel using rayon
    let file_infos: Vec<ShadowFileInfo> = shadow_files
        .par_iter()
        .map(|shadow_file| get_shadow_file_info(shadow_file, &password))
        .filter_map(Result::ok)
        .collect();

    let info_list: FileInfoList = FileInfoList::new(file_infos);

    ui::display_file_info_list(&info_list);
    Ok(())
}

fn decipher_original_filename(header: FileHeader, password: &SecureString) -> Option<SecureString> {
    let filename_nonce: &[u8; 24] = &header.filename_nonce;
    let filename_ciphertext: &[u8] = header.filename_ciphertext.as_slice();

    let salt: &[u8; 16] = &header.salt;
    let kdf_params: KeyDerivationParams = get_kdf_params(&header);
    // The header is untrusted input: bound the KDF cost before deriving,
    // otherwise a crafted file could request an enormous allocation.
    validate_untrusted_kdf_params(
        kdf_params.memory_cost,
        kdf_params.time_cost,
        kdf_params.parallelism,
        kdf_params.key_size,
    )
    .ok()?;
    let (key, _): (SecureKey, _) = with_kdf_memory_permit(kdf_params.memory_cost, || {
        derive_key(password.as_str().as_bytes(), salt, &kdf_params)
    })
    .ok()?;

    let (filename_bytes, _): (SecureBytes, _) =
        decrypt_bytes(filename_ciphertext, key.as_bytes(), filename_nonce).ok()?;

    parse_string_from_bytes(&filename_bytes).ok()
}

fn get_shadow_file_info(
    shadow_file: &ShadowFile,
    password: &SecureString,
) -> WorkflowResult<ShadowFileInfo> {
    let header = load_file_header(shadow_file)?;
    let original_filename: Option<SecureString> = decipher_original_filename(header, password);

    Ok(ShadowFileInfo::new(
        original_filename,
        shadow_file.filename.clone(),
        shadow_file.version.clone(),
        shadow_file.size,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_crypt_core::{
        profile::SecurityProfile,
        v1::{
            crypt::encrypt_bytes, header::FileHeader, key::KeyDerivationParams, key_ops::derive_key,
        },
    };

    #[test]
    fn test_decipher_original_filename_correct_password() {
        let password = "testpassword";
        let original_filename = "test.txt";
        let salt = [0u8; 16];
        let kdf_params = KeyDerivationParams::from(SecurityProfile::Test);
        let filename_nonce = [0u8; 24];

        // Derive key
        let (key, _) = derive_key(password.as_bytes(), &salt, &kdf_params).unwrap();

        // Encrypt filename
        let (filename_ciphertext, _) = encrypt_bytes(
            original_filename.as_bytes(),
            key.as_bytes(),
            &filename_nonce,
        )
        .unwrap();

        // Create header
        let header = FileHeader::new(
            salt,
            kdf_params,
            [0u8; 24], // content_nonce, not used
            filename_nonce,
            filename_ciphertext,
        );

        // Test decipher
        let password_secure = SecureString::new(password.to_string());
        let result = decipher_original_filename(header, &password_secure);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), original_filename);
    }

    #[test]
    fn test_decipher_original_filename_wrong_password() {
        let password = "testpassword";
        let wrong_password = "wrongpassword";
        let original_filename = "test.txt";
        let salt = [0u8; 16];
        let kdf_params = KeyDerivationParams::from(SecurityProfile::Test);
        let filename_nonce = [0u8; 24];

        // Derive key with correct password
        let (key, _) = derive_key(password.as_bytes(), &salt, &kdf_params).unwrap();

        // Encrypt filename
        let (filename_ciphertext, _) = encrypt_bytes(
            original_filename.as_bytes(),
            key.as_bytes(),
            &filename_nonce,
        )
        .unwrap();

        // Create header
        let header = FileHeader::new(
            salt,
            kdf_params,
            [0u8; 24],
            filename_nonce,
            filename_ciphertext,
        );

        // Test decipher with wrong password
        let wrong_password_secure = SecureString::new(wrong_password.to_string());
        let result = decipher_original_filename(header, &wrong_password_secure);

        assert!(result.is_none());
    }

    #[test]
    fn test_decipher_rejects_oversized_kdf_params_without_deriving() {
        // A crafted header claiming an enormous memory cost must be rejected
        // before any key derivation is attempted. If validation were missing,
        // this test would attempt a multi-terabyte allocation.
        let kdf_params = KeyDerivationParams::new(u32::MAX, u32::MAX, u32::MAX, u8::MAX);
        let header = FileHeader::new([0u8; 16], kdf_params, [0u8; 24], [0u8; 24], vec![1, 2, 3]);

        let password = SecureString::new("testpassword".to_string());
        let result = decipher_original_filename(header, &password);

        assert!(result.is_none());
    }
}
