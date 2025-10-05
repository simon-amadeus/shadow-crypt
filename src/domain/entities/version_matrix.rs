//! Version Compatibility Matrix for Shadow Format Evolution
//!
//! This module manages version compatibility relationships and migration paths
//! across Shadow file format versions, ensuring safe evolution and data preservation.
//!
//! ## Shadow Version Strategy
//!
//! - **V1 (Current)**: New baseline with proven TLV extensible headers
//! - **V3 (Legacy)**: Migration source only, preserved for compatibility
//! - **V2+ (Future)**: Forward evolution path with backward compatibility
//!
//! ## Migration Philosophy
//!
//! - **One-Way Progress**: Legacy → Current, never reverse to prevent technical debt
//! - **Data Preservation**: All cryptographic material and metadata maintained
//! - **Password Required**: Migration requires decryption/re-encryption for security
//! - **Format Evolution**: V1 → V2+ when new features justify format changes
//!
//! ## Compatibility Matrix Design
//!
//! The version matrix prevents dangerous operations while enabling safe evolution:
//! - Cross-version compatibility explicitly defined
//! - Migration paths with clear requirements and limitations
//! - Unknown version handling defaults to incompatible (safe failure mode)
//! - Future version support designed for seamless integration

use std::collections::{HashMap, HashSet};

/// Version compatibility relationship between format versions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionCompatibility {
    /// Can read/write directly without conversion
    Compatible,
    /// Can read but requires migration to write
    RequiresMigration,
    /// Cannot process at all
    Incompatible,
}

/// Type of migration required between versions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationType {
    /// Header format change only, data preserved
    HeaderMigration,
    /// Data format change, may require re-encryption
    DataMigration,
    /// Complete format overhaul
    FullMigration,
}

/// Migration path between two specific versions
#[derive(Debug, Clone)]
pub struct MigrationPath {
    pub from_version: u16,
    pub to_version: u16,
    pub migration_type: MigrationType,
    pub is_reversible: bool,
    pub requires_password: bool,
}

/// Version compatibility matrix managing format evolution
#[derive(Debug, Clone)]
pub struct VersionMatrix {
    /// Current baseline version for new files
    current_baseline: u16,
    /// Set of all versions this implementation can read
    readable_versions: HashSet<u16>,
    /// Set of all versions this implementation can write
    writable_versions: HashSet<u16>,
    /// Compatibility relationships between version pairs
    compatibility_map: HashMap<(u16, u16), VersionCompatibility>,
    /// Available migration paths
    migration_paths: HashMap<(u16, u16), MigrationPath>,
}

impl VersionMatrix {
    /// Create version matrix for Shadow rewrite (V1 baseline)
    pub fn new_shadow_rewrite() -> Self {
        let mut matrix = VersionMatrix {
            current_baseline: 1, // V1 is new baseline
            readable_versions: HashSet::new(),
            writable_versions: HashSet::new(),
            compatibility_map: HashMap::new(),
            migration_paths: HashMap::new(),
        };

        // Setup V1 (current baseline) - derived from legacy V3 TLV format
        matrix.readable_versions.insert(1);
        matrix.writable_versions.insert(1);
        
        // Setup legacy V3 compatibility (migration target)
        matrix.readable_versions.insert(3);
        // Note: V3 not in writable_versions - can read but must migrate to V1

        // V1 ↔ V1: Perfect compatibility
        matrix.compatibility_map.insert((1, 1), VersionCompatibility::Compatible);
        
        // V3 → V1: Requires migration (legacy to new baseline)
        matrix.compatibility_map.insert((3, 1), VersionCompatibility::RequiresMigration);
        matrix.migration_paths.insert((3, 1), MigrationPath {
            from_version: 3,
            to_version: 1,
            migration_type: MigrationType::HeaderMigration, // TLV structure preserved
            is_reversible: false, // No going back to legacy
            requires_password: true, // Need to decrypt/re-encrypt with new header
        });

        // V1 → V3: Incompatible (no reverse migration)
        matrix.compatibility_map.insert((1, 3), VersionCompatibility::Incompatible);

        // Unknown versions: Incompatible by default
        // This is handled by `is_compatible` method's fallback

        matrix
    }

    /// Check if reading a file version is compatible with target version
    pub fn is_compatible(&self, file_version: u16, target_version: u16) -> VersionCompatibility {
        // Check explicit compatibility map first
        if let Some(compatibility) = self.compatibility_map.get(&(file_version, target_version)) {
            return compatibility.clone();
        }

        // Fallback logic for unknown combinations
        if file_version == target_version {
            if self.readable_versions.contains(&file_version) {
                VersionCompatibility::Compatible
            } else {
                VersionCompatibility::Incompatible
            }
        } else {
            VersionCompatibility::Incompatible
        }
    }

    /// Check if migration is possible between versions
    pub fn can_migrate(&self, from_version: u16, to_version: u16) -> bool {
        matches!(
            self.is_compatible(from_version, to_version),
            VersionCompatibility::Compatible | VersionCompatibility::RequiresMigration
        )
    }

    /// Get migration path if available
    pub fn get_migration_path(&self, from_version: u16, to_version: u16) -> Option<&MigrationPath> {
        self.migration_paths.get(&(from_version, to_version))
    }

    /// Get current baseline version for new files
    pub fn current_baseline(&self) -> u16 {
        self.current_baseline
    }

    /// Check if version can be read by this implementation
    pub fn can_read(&self, version: u16) -> bool {
        self.readable_versions.contains(&version)
    }

    /// Check if version can be written by this implementation
    pub fn can_write(&self, version: u16) -> bool {
        self.writable_versions.contains(&version)
    }

    /// Get all readable versions
    pub fn readable_versions(&self) -> &HashSet<u16> {
        &self.readable_versions
    }

    /// Get all writable versions
    pub fn writable_versions(&self) -> &HashSet<u16> {
        &self.writable_versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_baseline_compatibility() {
        let matrix = VersionMatrix::new_shadow_rewrite();
        
        // V1 is current baseline
        assert_eq!(matrix.current_baseline(), 1);
        
        // V1 ↔ V1 perfect compatibility
        assert_eq!(
            matrix.is_compatible(1, 1),
            VersionCompatibility::Compatible
        );
        
        // Can read and write V1
        assert!(matrix.can_read(1));
        assert!(matrix.can_write(1));
    }

    #[test]
    fn test_legacy_v3_migration() {
        let matrix = VersionMatrix::new_shadow_rewrite();
        
        // Can read legacy V3 but cannot write it
        assert!(matrix.can_read(3));
        assert!(!matrix.can_write(3));
        
        // V3 → V1 requires migration
        assert_eq!(
            matrix.is_compatible(3, 1),
            VersionCompatibility::RequiresMigration
        );
        
        // Migration path should exist
        assert!(matrix.can_migrate(3, 1));
        let path = matrix.get_migration_path(3, 1).unwrap();
        assert_eq!(path.from_version, 3);
        assert_eq!(path.to_version, 1);
        assert_eq!(path.migration_type, MigrationType::HeaderMigration);
        assert!(!path.is_reversible);
        assert!(path.requires_password);
    }

    #[test]
    fn test_reverse_migration_blocked() {
        let matrix = VersionMatrix::new_shadow_rewrite();
        
        // V1 → V3 should be incompatible (no reverse migration)
        assert_eq!(
            matrix.is_compatible(1, 3),
            VersionCompatibility::Incompatible
        );
        
        assert!(!matrix.can_migrate(1, 3));
        assert!(matrix.get_migration_path(1, 3).is_none());
    }

    #[test]
    fn test_unknown_version_handling() {
        let matrix = VersionMatrix::new_shadow_rewrite();
        
        // Unknown versions should be incompatible
        assert_eq!(
            matrix.is_compatible(99, 1),
            VersionCompatibility::Incompatible
        );
        
        assert_eq!(
            matrix.is_compatible(1, 99),
            VersionCompatibility::Incompatible
        );
        
        // Cannot read/write unknown versions
        assert!(!matrix.can_read(99));
        assert!(!matrix.can_write(99));
    }

    #[test]
    fn test_migration_requirements() {
        let matrix = VersionMatrix::new_shadow_rewrite();
        
        let path = matrix.get_migration_path(3, 1).unwrap();
        
        // Legacy V3 → V1 migration characteristics
        assert_eq!(path.migration_type, MigrationType::HeaderMigration);
        assert!(path.requires_password); // Need to decrypt/re-encrypt
        assert!(!path.is_reversible); // No going back to legacy
    }
}