//! # Secure Key Material Entity
//!
//! Domain entity representing cryptographic key material with secure memory management.
//! This is a core security primitive that belongs in the domain layer.

use super::memory::SecureBox;

/// Key material container with automatic zeroization
/// 
/// KeyMaterial provides a secure container for cryptographic key data
/// that automatically zeroizes the key bytes when dropped. This follows
/// the patterns proven in the legacy implementation.
#[derive(Debug)]
pub struct KeyMaterial {
    /// Master key derived from password and salt
    pub master_key: SecureBox<[u8; 32]>,
    /// Key used for file encryption/decryption  
    pub encryption_key: SecureBox<[u8; 32]>,
    /// Key used for filename obfuscation
    pub obfuscation_key: SecureBox<[u8; 32]>,
}

impl PartialEq for KeyMaterial {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        
        self.master_key.expose_secret().ct_eq(other.master_key.expose_secret()).into() &&
        self.encryption_key.expose_secret().ct_eq(other.encryption_key.expose_secret()).into() &&
        self.obfuscation_key.expose_secret().ct_eq(other.obfuscation_key.expose_secret()).into()
    }
}

impl Eq for KeyMaterial {}

impl KeyMaterial {
    /// Create new key material from derived keys
    /// 
    /// All provided keys will be moved into SecureBoxes and automatically
    /// zeroized when the KeyMaterial is dropped.
    pub fn new(
        master_key: [u8; 32],
        encryption_key: [u8; 32], 
        obfuscation_key: [u8; 32],
    ) -> Self {
        Self {
            master_key: SecureBox::new(master_key),
            encryption_key: SecureBox::new(encryption_key),
            obfuscation_key: SecureBox::new(obfuscation_key),
        }
    }

    /// Create key material from master key using key derivation
    /// 
    /// Derives encryption and obfuscation keys from the master key using
    /// secure key derivation function (KDF).
    pub fn from_master_key(master_key: [u8; 32]) -> Self {
        // Use HKDF to derive separate keys from master key
        use sha2::Sha256;
        use hkdf::Hkdf;
        
        let hkdf = Hkdf::<Sha256>::new(None, &master_key);
        
        let mut encryption_key = [0u8; 32];
        let mut obfuscation_key = [0u8; 32];
        
        hkdf.expand(b"encryption", &mut encryption_key)
            .expect("HKDF encryption key derivation should not fail");
        hkdf.expand(b"obfuscation", &mut obfuscation_key)
            .expect("HKDF obfuscation key derivation should not fail");
        
        Self::new(master_key, encryption_key, obfuscation_key)
    }

    /// Get total key material length (for compatibility with tests)
    /// 
    /// Returns the total number of bytes in all contained keys.
    pub fn len(&self) -> usize {
        // 32 bytes each for master_key, encryption_key, obfuscation_key
        96
    }

    /// Get encryption key bytes for cipher initialization
    /// 
    /// Returns a reference to the encryption key bytes. This method provides
    /// minimal necessary access to key material for cryptographic operations
    /// while maintaining security through SecureBox protection.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.encryption_key.expose_secret()
    }
}