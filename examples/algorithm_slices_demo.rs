// Example showing the new vertically-sliced crypto architecture
// This demonstrates how algorithms are now organized and used

use shadow_core::crypto::algorithms::{argon2, xchacha20_poly1305};
use shadow_core::memory::{SecureKey, SecureString};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // === Argon2 Algorithm Slice ===
    
    // Use Argon2 for key derivation with different security profiles
    let password = SecureString::new("my_secure_password".to_string());
    let salt = [42u8; 16];
    
    // Test profile for development
    let test_profile = argon2::SecurityProfile::Test;
    let test_argon2 = test_profile.create_argon2();
    let _test_key = argon2::derive_key(&password, &salt, &test_argon2)?;
    
    // Production profile for real use
    let prod_profile = argon2::SecurityProfile::Production;
    let prod_argon2 = prod_profile.create_argon2();
    let master_key = argon2::derive_key(&password, &salt, &prod_argon2)?;
    
    // Derive filename key using HKDF
    let filename_key = argon2::derive_filename_key(&master_key)?;
    
    // === XChaCha20-Poly1305 Algorithm Slice ===
    
    // Use XChaCha20-Poly1305 for encryption
    let plaintext = b"This is my secret data";
    let nonce = [1u8; 24];
    let aad = b"associated_data";
    
    // Encrypt content
    let ciphertext = xchacha20_poly1305::encrypt(plaintext, &master_key, &nonce, aad)?;
    
    // Decrypt content
    let decrypted = xchacha20_poly1305::decrypt(&ciphertext, &master_key, &nonce, aad)?;
    assert_eq!(plaintext, decrypted.as_slice());
    
    // Encrypt filename
    let filename = "secret_document.txt";
    let encrypted_filename = xchacha20_poly1305::encrypt_filename(filename, &filename_key, &nonce)?;
    let decrypted_filename = xchacha20_poly1305::decrypt_filename(&encrypted_filename, &filename_key, &nonce)?;
    assert_eq!(filename, decrypted_filename);
    
    println!("✅ All crypto operations successful!");
    println!("📁 Algorithm: XChaCha20-Poly1305 (ID: {})", xchacha20_poly1305::ALGORITHM_ID);
    println!("🔑 Key size: {} bytes", xchacha20_poly1305::KEY_SIZE);
    println!("🎲 Nonce size: {} bytes", xchacha20_poly1305::NONCE_SIZE);
    println!("🧂 Salt size: {} bytes", argon2::SALT_SIZE);
    
    Ok(())
}