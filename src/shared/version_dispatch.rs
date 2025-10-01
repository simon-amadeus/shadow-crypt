//! Version dispatcher for Shadow file format
//! 
//! This module provides high-level version dispatch functionality
//! to route operations to appropriate version-specific handlers.

use crate::shared::errors::CryptoError;
use crate::shared::versioning::{VersionedHeader, HeaderV1, detect_version, CompatibilityMatrix};

/// Unified header interface that dispatches to version-specific implementations
#[derive(Debug)]
pub enum AnyHeader {
    V1(HeaderV1),
    // Future versions will be added here
    // V2(HeaderV2),
    // V3(HeaderV3),
}

impl AnyHeader {
    /// Create a new header of the current version
    pub fn new_current(
        algorithm_id: crate::shared::algorithms::AlgorithmId,
        salt: [u8; 16],
        nonce: [u8; 12],
    ) -> Self {
        // Always create the current version (V1 for now)
        AnyHeader::V1(HeaderV1::new(algorithm_id, salt, nonce))
    }
    
    /// Deserialize a header from bytes, auto-detecting version
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError> {
        let version = detect_version(data)?;
        
        match version {
            1 => {
                let (header_v1, offset) = HeaderV1::deserialize(data)?;
                Ok((AnyHeader::V1(header_v1), offset))
            }
            // Future versions will be handled here
            // 2 => {
            //     let (header_v2, offset) = HeaderV2::deserialize(data)?;
            //     Ok((AnyHeader::V2(header_v2), offset))
            // }
            _ => Err(CryptoError::HeaderParsingError(
                format!("Unsupported version: {}", version)
            )),
        }
    }
    
    /// Serialize the header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            AnyHeader::V1(header) => header.serialize(),
            // Future versions will be handled here
        }
    }
    
    /// Validate the header
    pub fn validate(&self) -> Result<(), CryptoError> {
        match self {
            AnyHeader::V1(header) => header.validate(),
            // Future versions will be handled here
        }
    }
    
    /// Get the version number
    pub fn version(&self) -> u16 {
        match self {
            AnyHeader::V1(_) => HeaderV1::VERSION,
            // Future versions will be handled here
        }
    }
    
    /// Check if this header can migrate to a target version
    pub fn can_migrate_to(&self, target_version: u16) -> bool {
        match self {
            AnyHeader::V1(_) => HeaderV1::can_migrate_to(target_version),
            // Future versions will be handled here
        }
    }
    
    /// Get migration paths from this version
    pub fn migration_paths(&self) -> Vec<u16> {
        CompatibilityMatrix::migration_paths(self.version())
    }
    
    /// Get algorithm ID
    pub fn algorithm_id(&self) -> crate::shared::algorithms::AlgorithmId {
        match self {
            AnyHeader::V1(header) => header.algorithm_id,
            // Future versions will be handled here
        }
    }
    
    /// Get salt
    pub fn salt(&self) -> [u8; 16] {
        match self {
            AnyHeader::V1(header) => header.salt,
            // Future versions will be handled here
        }
    }
    
    /// Get nonce
    pub fn nonce(&self) -> [u8; 12] {
        match self {
            AnyHeader::V1(header) => header.nonce,
            // Future versions will be handled here
        }
    }
    
    /// Get magic bytes for this version
    pub fn magic(&self) -> &'static [u8] {
        match self {
            AnyHeader::V1(_) => HeaderV1::magic(),
            // Future versions will be handled here
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
        
        // For now, only support direct migration from V1 to future versions
        // More complex migration chains can be added later
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
            (1, 1) => {
                // No migration needed - same version
                Ok(source)
            }
            (1, v) if v > 1 => {
                // Future: implement actual migration logic here
                Err(CryptoError::HeaderParsingError(
                    format!("Migration from V1 to V{} not yet implemented", v)
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
        let header = AnyHeader::new_current(
            AlgorithmId::AesGcm256,
            [1u8; 16],
            [2u8; 12],
        );
        
        assert_eq!(header.version(), 1);
        assert_eq!(header.algorithm_id(), AlgorithmId::AesGcm256);
        assert_eq!(header.salt(), [1u8; 16]);
        assert_eq!(header.nonce(), [2u8; 12]);
    }
    
    #[test]
    fn test_version_detection_and_dispatch() {
        let header = AnyHeader::new_current(
            AlgorithmId::AesGcm256,
            [1u8; 16],
            [2u8; 12],
        );
        
        let serialized = header.serialize();
        let (deserialized, _offset) = AnyHeader::deserialize(&serialized).unwrap();
        
        assert_eq!(deserialized.version(), 1);
        assert_eq!(deserialized.algorithm_id(), AlgorithmId::AesGcm256);
    }
    
    #[test]
    fn test_migration_capabilities() {
        let header = AnyHeader::new_current(
            AlgorithmId::AesGcm256,
            [1u8; 16],
            [2u8; 12],
        );
        
        assert!(header.can_migrate_to(2));
        assert!(!header.can_migrate_to(100));
        
        let paths = header.migration_paths();
        assert!(!paths.is_empty());
    }
    
    #[test]
    fn test_migration_planner() {
        assert!(VersionMigrator::can_migrate(1, 2));
        assert!(!VersionMigrator::can_migrate(1, 100));
        
        let plan = VersionMigrator::create_migration_plan(1, 2).unwrap();
        assert_eq!(plan.source_version, 1);
        assert_eq!(plan.target_version, 2);
        assert_eq!(plan.steps.len(), 1);
    }
}