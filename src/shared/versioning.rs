//! Versioning system for Shadow file format
//! 
//! This module implements proper versioned types and migration chains
//! to enable robust migration between different Shadow file format versions.

use crate::shared::errors::CryptoError;

// Re-export V3 header from versions module (will be renamed to V1)
pub use crate::shared::versions::v3::HeaderV3;

/// Trait for version-specific header implementations
pub trait VersionedHeader: Sized {
    /// The version number this header represents
    const VERSION: u16;
    
    /// Serialize this header to bytes
    fn serialize(&self) -> Vec<u8>;
    
    /// Deserialize from bytes
    fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError>;
    
    /// Validate this header's format
    fn validate(&self) -> Result<(), CryptoError>;
    
    /// Get the magic bytes for this version
    fn magic() -> &'static [u8];
    
    /// Check if this version can migrate to another version
    fn can_migrate_to(target_version: u16) -> bool;
    
    /// Check if this version can migrate from another version
    fn can_migrate_from(source_version: u16) -> bool;
}

/// Version detection from raw header data
pub fn detect_version(data: &[u8]) -> Result<u16, CryptoError> {
    if data.len() < 8 {
        return Err(CryptoError::HeaderParsingError(
            "Insufficient data to detect version".to_string()
        ));
    }
    
    // Check magic first
    let magic = &data[0..6];
    if magic != b"SHADOW" {
        return Err(CryptoError::HeaderParsingError(
            format!("Invalid magic number: expected 'SHADOW', got {:?}", 
                String::from_utf8_lossy(magic))
        ));
    }
    
    // Extract version
    let version = u16::from_le_bytes([data[6], data[7]]);
    Ok(version)
}

/// Compatibility matrix for version migration
pub struct CompatibilityMatrix;

impl CompatibilityMatrix {
    /// Check if source version can migrate to target version
    pub fn can_migrate(source_version: u16, target_version: u16) -> bool {
        match source_version {
            3 => HeaderV3::can_migrate_to(target_version),
            // Future versions will add their logic here
            _ => false,
        }
    }
    
    /// Get supported migration paths from a version
    pub fn migration_paths(source_version: u16) -> Vec<u16> {
        match source_version {
            3 => (4..=10).filter(|&v| HeaderV3::can_migrate_to(v)).collect(),
            // Future versions will add their paths here
            _ => vec![],
        }
    }
    
    /// Check if a version is supported for reading
    pub fn can_read(version: u16) -> bool {
        match version {
            3 => true,
            // Future versions will add support here
            _ => false,
        }
    }
    
    /// Check if a version is supported for writing
    pub fn can_write(version: u16) -> bool {
        match version {
            3 => true,
            // Future versions will add support here
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version_detection() {
        let mut data = vec![0u8; 100];
        data[0..6].copy_from_slice(b"SHADOW");
        data[6..8].copy_from_slice(&3u16.to_le_bytes());  // Changed to version 3
        
        assert_eq!(detect_version(&data).unwrap(), 3);
    }
    
    #[test]
    fn test_migration_capabilities() {
        assert!(HeaderV3::can_migrate_to(4));  // Changed to V3
        assert!(!HeaderV3::can_migrate_to(100));
    }
    
    #[test]
    fn test_compatibility_matrix() {
        assert!(CompatibilityMatrix::can_read(3));  // Changed to version 3
        assert!(CompatibilityMatrix::can_write(3));
        assert!(!CompatibilityMatrix::can_read(0));
        assert!(!CompatibilityMatrix::can_read(100));
        
        assert!(CompatibilityMatrix::can_migrate(3, 4));  // Changed to V3->V4
        assert!(!CompatibilityMatrix::can_migrate(3, 100));
        
        let paths = CompatibilityMatrix::migration_paths(3);  // Changed to V3
        assert!(!paths.is_empty());
        assert!(paths.contains(&4));  // Changed to expect V4
    }
}