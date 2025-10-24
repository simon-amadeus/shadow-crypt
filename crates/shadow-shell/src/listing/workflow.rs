use std::sync::Arc;

use rayon::prelude::*;
use shadow_core::{
    memory::{SecureBytes, SecureKey, SecureString},
    v1::{
        crypt::decrypt_bytes, header::FileHeader, header_ops::get_kdf_params,
        key::KeyDerivationParams, key_ops::derive_key,
    },
};

use crate::{
    errors::WorkflowResult,
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
    let (key, _): (SecureKey, _) =
        derive_key(password.as_str().as_bytes(), salt, &kdf_params).ok()?;

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
