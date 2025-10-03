//! Algorithm identification and versioning for cryptographic agility
//! 
//! This module handles algorithm identifiers and version management
//! to support future cryptographic algorithm upgrades.

/// Algorithm identifiers for cryptographic agility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AlgorithmId {
    AesGcm256 = 0x0001,
    ChaCha20Poly1305 = 0x0002,  // Future algorithm
    
    // Post-quantum cryptography (reserved range 0x1000-0x1FFF)
    KyberAes256 = 0x1001,       // Future: CRYSTALS-Kyber + AES-256-GCM
    KyberChaCha20 = 0x1002,     // Future: CRYSTALS-Kyber + ChaCha20-Poly1305
    DilithiumAes256 = 0x1003,   // Future: CRYSTALS-Dilithium + AES-256-GCM
    
    // Streaming algorithms (reserved range 0x2000-0x2FFF)
    AesGcmStreaming = 0x2001,   // Future: Chunked AES-GCM for large files
}

impl From<u16> for AlgorithmId {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => AlgorithmId::AesGcm256,
            0x0002 => AlgorithmId::ChaCha20Poly1305,
            0x1001 => AlgorithmId::KyberAes256,
            0x1002 => AlgorithmId::KyberChaCha20,
            0x1003 => AlgorithmId::DilithiumAes256,
            0x2001 => AlgorithmId::AesGcmStreaming,
            _ => AlgorithmId::AesGcm256, // Default fallback
        }
    }
}

impl AlgorithmId {
    /// Get human-readable name for the algorithm
    pub fn name(self) -> &'static str {
        match self {
            AlgorithmId::AesGcm256 => "AES-256-GCM",
            AlgorithmId::ChaCha20Poly1305 => "XChaCha20-Poly1305",
            AlgorithmId::KyberAes256 => "CRYSTALS-Kyber + AES-256-GCM",
            AlgorithmId::KyberChaCha20 => "CRYSTALS-Kyber + XChaCha20-Poly1305",
            AlgorithmId::DilithiumAes256 => "CRYSTALS-Dilithium + AES-256-GCM",
            AlgorithmId::AesGcmStreaming => "AES-256-GCM (Streaming)",
        }
    }
    
    /// Convert to u16 identifier
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Padding constants to prevent information leakage
pub const MAX_FILENAME_LENGTH: usize = 512;     // Pad all filenames to this size
pub const MAX_DIRECTORY_PATH_LENGTH: usize = 2048;  // Pad all paths to this size  
pub const MAX_METADATA_LENGTH: usize = 256;     // Pad all metadata to this size

/// Current Shadow format version (V1 remains default for compatibility)
pub const CURRENT_VERSION: u16 = 1;

/// Minimum supported version for backward compatibility
pub const MIN_SUPPORTED_VERSION: u16 = 1;

/// Maximum supported version for forward compatibility
pub const MAX_SUPPORTED_VERSION: u16 = 3;

/// Version information for migration decisions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    pub current: u16,
    pub min_supported: u16,
    pub max_supported: u16,
    pub is_current: bool,
    pub is_supported: bool,
    pub needs_migration: bool,
    pub can_migrate: bool,
}

impl Default for VersionInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionInfo {
    pub fn new() -> Self {
        Self {
            current: CURRENT_VERSION,
            min_supported: MIN_SUPPORTED_VERSION,
            max_supported: MAX_SUPPORTED_VERSION,
            is_current: true,
            is_supported: true,
            needs_migration: false,
            can_migrate: true,
        }
    }
    
    /// Create version info for a specific version
    pub fn for_version(version: u16) -> Self {
        let is_current = version == CURRENT_VERSION;
        let is_supported = (MIN_SUPPORTED_VERSION..=MAX_SUPPORTED_VERSION).contains(&version);
        let needs_migration = !is_current && is_supported;
        let can_migrate = is_supported;
        
        Self {
            current: version,
            min_supported: MIN_SUPPORTED_VERSION,
            max_supported: MAX_SUPPORTED_VERSION,
            is_current,
            is_supported,
            needs_migration,
            can_migrate,
        }
    }
    
    pub fn is_supported(&self, version: u16) -> bool {
        version >= self.min_supported && version <= self.max_supported
    }
    
    pub fn is_compatible(&self, version: u16) -> bool {
        self.is_supported(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_id_conversion() {
        assert_eq!(AlgorithmId::from(0x0001), AlgorithmId::AesGcm256);
        assert_eq!(AlgorithmId::from(0x0002), AlgorithmId::ChaCha20Poly1305);
        assert_eq!(AlgorithmId::from(0x1001), AlgorithmId::KyberAes256);
        assert_eq!(AlgorithmId::from(0x9999), AlgorithmId::AesGcm256); // Fallback
    }

    #[test]
    fn test_version_info() {
        let version_info = VersionInfo::new();
        assert!(version_info.is_supported(1));
        assert!(version_info.is_compatible(1));
        assert!(!version_info.is_supported(0));
        assert!(!version_info.is_supported(999));
    }
}