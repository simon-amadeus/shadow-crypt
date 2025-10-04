//! Version dispatcher for Shadow file format
//! 
//! This module provides high-level version dispatch functionality
//! to route operations to appropriate version-specific handlers.

use crate::shared::errors::CryptoError;
use crate::shared::versioning::{VersionedHeader, HeaderV3, detect_version, CompatibilityMatrix};

/// Unified header interface that dispatches to version-specific implementations
#[derive(Debug)]
pub enum AnyHeader {
    V3(HeaderV3),
    // Future versions will be added here
}

impl AnyHeader {
    /// Create a new header of the current version (V3)
    pub fn new_current(
        algorithm_id: crate::shared::algorithms::AlgorithmId,
        nonce: Vec<u8>,
        salt: [u8; 32],
    ) -> Self {
        AnyHeader::V3(HeaderV3::new(algorithm_id, nonce, salt))
    }
    
    /// Deserialize a header from bytes, auto-detecting version
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError> {
        let version = detect_version(data)?;
        
        match version {
            3 => {
                let (header_v3, offset) = HeaderV3::deserialize(data)?;
                Ok((AnyHeader::V3(header_v3), offset))
            }
            // Future versions will be handled here
            _ => Err(CryptoError::HeaderParsingError(
                format!("Unsupported version: {}", version)
            )),
        }
    }
    
    /// Serialize the header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            AnyHeader::V3(header) => header.serialize(),
        }
    }
    
    /// Validate the header
    pub fn validate(&self) -> Result<(), CryptoError> {
        match self {
            AnyHeader::V3(header) => header.validate(),
        }
    }
    
    /// Get the version number
    pub fn version(&self) -> u16 {
        match self {
            AnyHeader::V3(_) => HeaderV3::VERSION,
        }
    }
    
    /// Check if this header can migrate to a target version
    pub fn can_migrate_to(&self, target_version: u16) -> bool {
        match self {
            AnyHeader::V3(_) => HeaderV3::can_migrate_to(target_version),
        }
    }
    
    /// Get migration paths from this version
    pub fn migration_paths(&self) -> Vec<u16> {
        CompatibilityMatrix::migration_paths(self.version())
    }
    
    /// Get algorithm ID
    pub fn algorithm_id(&self) -> crate::shared::algorithms::AlgorithmId {
        match self {
            AnyHeader::V3(header) => header.algorithm_id,
        }
    }
    
    /// Get salt (returns full 32-byte salt)
    pub fn salt(&self) -> [u8; 32] {
        match self {
            AnyHeader::V3(header) => header.salt,
        }
    }
    
    /// Get full salt as Vec
    pub fn salt_full(&self) -> Vec<u8> {
        match self {
            AnyHeader::V3(header) => header.salt.to_vec(),
        }
    }
    
    /// Get nonce as Vec
    pub fn nonce(&self) -> Vec<u8> {
        match self {
            AnyHeader::V3(header) => header.nonce.clone(),
        }
    }
    
    /// Get full nonce (alias for compatibility)
    pub fn nonce_full(&self) -> Vec<u8> {
        match self {
            AnyHeader::V3(header) => header.nonce.clone(),
        }
    }
    
    /// Get magic bytes for this version
    pub fn magic(&self) -> &'static [u8] {
        match self {
            AnyHeader::V3(_) => HeaderV3::magic(),
        }
    }
}

/// Migration operations between versions
pub struct VersionMigrator;

impl VersionMigrator {
    /// Check if migration is possible between two versions
    pub fn can_migrate(source_version: u16, target_version: u16) -> bool {
        CompatibilityMatrix::can_migrate(source_version, target_version)
    }
    
    /// Create a migration plan between versions
    pub fn create_migration_plan(source_version: u16, target_version: u16) -> Result<MigrationPlan, CryptoError> {
        if !Self::can_migrate(source_version, target_version) {
            return Err(CryptoError::HeaderParsingError(
                format!("Cannot migrate from version {} to {}", source_version, target_version)
            ));
        }
        
        // Support migration from V3 to future versions
        Ok(MigrationPlan {
            source_version,
            target_version,
            steps: vec![MigrationStep {
                from: source_version,
                to: target_version,
                operation: MigrationOperation::DirectConvert,
            }],
        })
    }
    
    /// Execute a migration (placeholder for future implementation)
    pub fn migrate_header(source: AnyHeader, target_version: u16) -> Result<AnyHeader, CryptoError> {
        let source_version = source.version();
        match (source_version, target_version) {
            (3, 3) => {
                // No migration needed - same version
                Ok(source)
            }
            (3, v) if v > 3 => {
                // Future: implement actual migration logic here
                Err(CryptoError::HeaderParsingError(
                    format!("Migration from V3 to V{} not yet implemented", v)
                ))
            }
            _ => Err(CryptoError::HeaderParsingError(
                "Unsupported migration path".to_string()
            )),
        }
    }
}

/// Migration plan describing how to migrate between versions
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    pub source_version: u16,
    pub target_version: u16,
    pub steps: Vec<MigrationStep>,
}

/// Individual migration step
#[derive(Debug, Clone)]
pub struct MigrationStep {
    pub from: u16,
    pub to: u16,
    pub operation: MigrationOperation,
}

/// Type of migration operation
#[derive(Debug, Clone)]
pub enum MigrationOperation {
    DirectConvert,      // Direct conversion between compatible formats
    DataTransform,      // Data transformation required
    AlgorithmUpgrade,   // Cryptographic algorithm upgrade
    FormatExtension,    // Format extensions (backward compatible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::algorithms::AlgorithmId;
    
    #[test]
    fn test_any_header_creation() {
        let nonce = vec![1u8; 12];
        let salt = [2u8; 32];
        let header = AnyHeader::new_current(
            AlgorithmId::AesGcm256,
            nonce.clone(),
            salt,
        );
        
        assert_eq!(header.version(), 3);
        assert_eq!(header.algorithm_id(), AlgorithmId::AesGcm256);
        assert_eq!(header.salt(), salt);
        assert_eq!(header.nonce(), nonce);
    }
    
    #[test]
    fn test_version_detection_and_dispatch() {
        let nonce = vec![1u8; 12];
        let salt = [2u8; 32];
        let header = AnyHeader::new_current(
            AlgorithmId::AesGcm256,
            nonce,
            salt,
        );
        
        let serialized = header.serialize();
        let (deserialized, _offset) = AnyHeader::deserialize(&serialized).unwrap();
        
        assert_eq!(deserialized.version(), 3);
        assert_eq!(deserialized.algorithm_id(), AlgorithmId::AesGcm256);
    }
    
    #[test]
    fn test_migration_capabilities() {
        let nonce = vec![1u8; 12];
        let salt = [2u8; 32];
        let header = AnyHeader::new_current(
            AlgorithmId::AesGcm256,
            nonce,
            salt,
        );
        
        assert!(header.can_migrate_to(4));
        assert!(!header.can_migrate_to(100));
        
        let paths = header.migration_paths();
        assert!(!paths.is_empty());
    }
    
    #[test]
    fn test_migration_planner() {
        assert!(VersionMigrator::can_migrate(3, 4));
        assert!(!VersionMigrator::can_migrate(3, 100));
        
        let plan = VersionMigrator::create_migration_plan(3, 4).unwrap();
        assert_eq!(plan.source_version, 3);
        assert_eq!(plan.target_version, 4);
        assert_eq!(plan.steps.len(), 1);
    }
}