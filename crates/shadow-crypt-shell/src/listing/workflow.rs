use std::sync::Arc;

use rayon::prelude::*;
use shadow_crypt_core::{memory::SecureString, vault::ParsedFile};

use crate::{
    errors::WorkflowResult,
    kdf::derive_untrusted_key,
    listing::{
        file::{FileInfoList, ListingInput, ShadowFile, ShadowFileInfo},
        file_ops::{load_file_header_bytes, scan_directory_for_shadow_files},
    },
    ui,
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

/// Version-agnostic: ParsedFile dispatches to the file's own format version.
fn decipher_original_filename(
    header_bytes: &[u8],
    password: &SecureString,
) -> Option<SecureString> {
    let parsed = ParsedFile::parse(header_bytes).ok()?;
    let key = derive_untrusted_key(&parsed, password).ok()?;
    parsed.decrypt_filename(&key).ok()
}

fn get_shadow_file_info(
    shadow_file: &ShadowFile,
    password: &SecureString,
) -> WorkflowResult<ShadowFileInfo> {
    let header_bytes = load_file_header_bytes(shadow_file)?;
    let original_filename: Option<SecureString> =
        decipher_original_filename(header_bytes.as_slice(), password);

    Ok(ShadowFileInfo::new(
        original_filename,
        shadow_file.filename.clone(),
        shadow_file.version,
        shadow_file.size,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_crypt_core::{profile::SecurityProfile, v1, v2};

    fn build_v1_header_bytes(password: &str, original_filename: &str) -> Vec<u8> {
        let salt = [0u8; 16];
        let kdf_params = v1::key::KeyDerivationParams::from(SecurityProfile::Test);
        let filename_nonce = [0u8; 24];

        let (key, _) = kdf_params.derive_key(password.as_bytes(), &salt).unwrap();
        let (filename_ciphertext, _) = v1::crypt::encrypt_bytes(
            original_filename.as_bytes(),
            key.as_bytes(),
            &filename_nonce,
        )
        .unwrap();

        let header = v1::header::FileHeader::new(
            salt,
            kdf_params,
            [0u8; 24], // content_nonce, not used
            filename_nonce,
            filename_ciphertext,
        );
        header.serialize()
    }

    fn build_v2_header_bytes(password: &str, original_filename: &str) -> Vec<u8> {
        let salt = [0u8; 16];
        let kdf_params = v2::key::KeyDerivationParams::from(SecurityProfile::Test);
        let content_nonce = [1u8; 24];
        let filename_nonce = [0u8; 24];

        let (key, _) = kdf_params.derive_key(password.as_bytes(), &salt).unwrap();
        let binding =
            v2::header::HeaderBinding::new(&salt, &kdf_params, &content_nonce, &filename_nonce);
        let (filename_ciphertext, _) = v2::crypt::encrypt_bytes(
            original_filename.as_bytes(),
            key.as_bytes(),
            &filename_nonce,
            &binding.aad(v2::header::AadPurpose::Filename),
        )
        .unwrap();

        let header = v2::header::FileHeader::new(
            salt,
            kdf_params,
            content_nonce,
            filename_nonce,
            filename_ciphertext,
        )
        .unwrap();
        header.serialize()
    }

    #[test]
    fn test_decipher_original_filename_correct_password_v1() {
        let header_bytes = build_v1_header_bytes("testpassword", "test.txt");
        let password = SecureString::new("testpassword".to_string());

        let result = decipher_original_filename(&header_bytes, &password);
        assert_eq!(result.unwrap().as_str(), "test.txt");
    }

    #[test]
    fn test_decipher_original_filename_wrong_password_v1() {
        let header_bytes = build_v1_header_bytes("testpassword", "test.txt");
        let password = SecureString::new("wrongpassword".to_string());

        let result = decipher_original_filename(&header_bytes, &password);
        assert!(result.is_none());
    }

    #[test]
    fn test_decipher_original_filename_correct_password_v2() {
        let header_bytes = build_v2_header_bytes("testpassword", "test.txt");
        let password = SecureString::new("testpassword".to_string());

        let result = decipher_original_filename(&header_bytes, &password);
        assert_eq!(result.unwrap().as_str(), "test.txt");
    }

    #[test]
    fn test_decipher_original_filename_wrong_password_v2() {
        let header_bytes = build_v2_header_bytes("testpassword", "test.txt");
        let password = SecureString::new("wrongpassword".to_string());

        let result = decipher_original_filename(&header_bytes, &password);
        assert!(result.is_none());
    }

    #[test]
    fn test_decipher_rejects_oversized_kdf_params_without_deriving() {
        // A crafted header claiming an enormous memory cost must be rejected
        // before any key derivation is attempted. If validation were missing,
        // this test would attempt a multi-terabyte allocation.
        let kdf_params = v1::key::KeyDerivationParams::new(u32::MAX, u32::MAX, u32::MAX, u8::MAX);
        let header =
            v1::header::FileHeader::new([0u8; 16], kdf_params, [0u8; 24], [0u8; 24], vec![1, 2, 3]);
        let header_bytes = header.serialize();

        let password = SecureString::new("testpassword".to_string());
        let result = decipher_original_filename(&header_bytes, &password);

        assert!(result.is_none());
    }
}
