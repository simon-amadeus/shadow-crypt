//! File format migration system
//! 
//! This module provides infrastructure for migrating encrypted files between
//! different versions of the Shadow file format. It includes:
//! - Version detection and compatibility checking
//! - Migration planning and verification
//! - Safety features like backup and rollback
//! - Future algorithm transition support

use crate::shared::errors::CryptoError;
use crate::shared::header::{Header, VersionInfo, CURRENT_VERSION, MIN_SUPPORTED_VERSION};
use std::path::{Path, PathBuf};
use std::fs;

/// Migration plan for a single file
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    pub source_path: PathBuf,
    pub source_version: u16,
    pub target_version: u16,
    pub requires_backup: bool,
    pub estimated_steps: usize,
    pub safety_checks: Vec<SafetyCheck>,
}

/// Safety checks to perform before migration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyCheck {
    VerifyFileIntegrity,
    CheckDiskSpace,
    ValidatePermissions,
    TestDecryption,
    CreateBackup,
}

/// Migration operation result
#[derive(Debug, Clone)]
pub struct MigrationResult {
    pub success: bool,
    pub original_version: u16,
    pub final_version: u16,
    pub backup_path: Option<PathBuf>,
    pub error: Option<String>,
    pub safety_checks_passed: Vec<SafetyCheck>,
}

/// Migration system for Shadow file format evolution
pub struct MigrationSystem {
    /// Whether to create backups before migration
    pub create_backups: bool,
    /// Whether to verify integrity after migration
    pub verify_after_migration: bool,
    /// Maximum number of files to migrate in batch
    pub batch_size: usize,
}

impl MigrationSystem {
    /// Create new migration system with default safety settings
    pub fn new() -> Self {
        Self {
            create_backups: true,
            verify_after_migration: true,
            batch_size: 100,
        }
    }

    /// Create migration system with custom safety settings
    pub fn with_settings(create_backups: bool, verify_after_migration: bool, batch_size: usize) -> Self {
        Self {
            create_backups,
            verify_after_migration,
            batch_size,
        }
    }

    /// Analyze a file and create migration plan
    pub fn analyze_file(&self, file_path: &Path) -> Result<Option<MigrationPlan>, CryptoError> {
        // Check if file exists and is readable
        if !file_path.exists() {
            return Err(CryptoError::FileSystemError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("File not found: {}", file_path.display())
            )));
        }

        // Read header to determine version
        let file_data = fs::read(file_path)
            .map_err(|e| CryptoError::FileSystemError(e))?;

        // Try to parse header
        let (header, _) = Header::deserialize(&file_data)
            .map_err(|e| CryptoError::HeaderParsingError(
                format!("Cannot analyze file {}: {}", file_path.display(), e)
            ))?;

        let version_info = header.get_version_info();

        // If file is already current version, no migration needed
        if version_info.is_current {
            return Ok(None);
        }

        // If file cannot be migrated, return error
        if !version_info.can_migrate {
            return Err(CryptoError::HeaderParsingError(
                format!("File {} version {} cannot be migrated (minimum supported: {})",
                       file_path.display(), version_info.current, MIN_SUPPORTED_VERSION)
            ));
        }

        // Create migration plan
        let plan = MigrationPlan {
            source_path: file_path.to_path_buf(),
            source_version: version_info.current,
            target_version: CURRENT_VERSION,
            requires_backup: self.create_backups,
            estimated_steps: self.estimate_migration_steps(version_info.current, CURRENT_VERSION),
            safety_checks: self.get_required_safety_checks(),
        };

        Ok(Some(plan))
    }

    /// Estimate number of steps required for migration
    fn estimate_migration_steps(&self, from_version: u16, to_version: u16) -> usize {
        let version_diff = (to_version - from_version) as usize;
        let base_steps = 3; // Read, Transform, Write
        let safety_steps = if self.create_backups { 2 } else { 0 }; // Backup, Verify
        let verification_steps = if self.verify_after_migration { 1 } else { 0 };
        
        base_steps + safety_steps + verification_steps + version_diff
    }

    /// Get list of required safety checks
    fn get_required_safety_checks(&self) -> Vec<SafetyCheck> {
        let mut checks = vec![
            SafetyCheck::VerifyFileIntegrity,
            SafetyCheck::CheckDiskSpace,
            SafetyCheck::ValidatePermissions,
        ];

        if self.create_backups {
            checks.push(SafetyCheck::CreateBackup);
        }

        if self.verify_after_migration {
            checks.push(SafetyCheck::TestDecryption);
        }

        checks
    }

    /// Analyze multiple files for batch migration
    pub fn analyze_directory(&self, dir_path: &Path) -> Result<Vec<MigrationPlan>, CryptoError> {
        let mut plans = Vec::new();

        if !dir_path.is_dir() {
            return Err(CryptoError::FileSystemError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is not a directory", dir_path.display())
            )));
        }

        // Scan for .shadow files
        let entries = fs::read_dir(dir_path)
            .map_err(|e| CryptoError::FileSystemError(e))?;

        for entry in entries {
            let entry = entry.map_err(|e| CryptoError::FileSystemError(e))?;
            let path = entry.path();

            // Only analyze .shadow files
            if path.extension().and_then(|s| s.to_str()) == Some("shadow") {
                match self.analyze_file(&path) {
                    Ok(Some(plan)) => plans.push(plan),
                    Ok(None) => continue, // File already current version
                    Err(e) => {
                        // Log error but continue with other files
                        eprintln!("Warning: Could not analyze {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(plans)
    }

    /// Execute migration plan (placeholder for future implementation)
    pub fn execute_migration(&self, _plan: &MigrationPlan) -> Result<MigrationResult, CryptoError> {
        // This is a placeholder for the actual migration implementation
        // which will be implemented in future phases when we have multiple
        // format versions to migrate between
        
        Err(CryptoError::HeaderParsingError(
            "Migration execution not yet implemented - this is infrastructure for future versions".to_string()
        ))
    }
}

impl Default for MigrationSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility function to check if a file needs migration
pub fn file_needs_migration(file_path: &Path) -> Result<bool, CryptoError> {
    let file_data = fs::read(file_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;

    let (header, _) = Header::deserialize(&file_data)?;
    Ok(header.needs_migration())
}

/// Utility function to get version info for a file
pub fn get_file_version_info(file_path: &Path) -> Result<VersionInfo, CryptoError> {
    let file_data = fs::read(file_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;

    let (header, _) = Header::deserialize(&file_data)?;
    Ok(header.get_version_info())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_system_creation() {
        let migration_system = MigrationSystem::new();
        assert!(migration_system.create_backups);
        assert!(migration_system.verify_after_migration);
        assert_eq!(migration_system.batch_size, 100);
    }

    #[test]
    fn test_migration_system_custom_settings() {
        let migration_system = MigrationSystem::with_settings(false, false, 50);
        assert!(!migration_system.create_backups);
        assert!(!migration_system.verify_after_migration);
        assert_eq!(migration_system.batch_size, 50);
    }

    #[test]
    fn test_estimate_migration_steps() {
        let migration_system = MigrationSystem::new();
        let steps = migration_system.estimate_migration_steps(1, 1);
        // Same version: base(3) + backup(2) + verification(1) + version_diff(0) = 6
        assert_eq!(steps, 6);
    }

    #[test]
    fn test_safety_checks_with_backups() {
        let migration_system = MigrationSystem::with_settings(true, true, 100);
        let checks = migration_system.get_required_safety_checks();
        assert!(checks.contains(&SafetyCheck::VerifyFileIntegrity));
        assert!(checks.contains(&SafetyCheck::CreateBackup));
        assert!(checks.contains(&SafetyCheck::TestDecryption));
    }

    #[test]
    fn test_safety_checks_without_backups() {
        let migration_system = MigrationSystem::with_settings(false, false, 100);
        let checks = migration_system.get_required_safety_checks();
        assert!(checks.contains(&SafetyCheck::VerifyFileIntegrity));
        assert!(!checks.contains(&SafetyCheck::CreateBackup));
        assert!(!checks.contains(&SafetyCheck::TestDecryption));
    }

    #[test]
    fn test_analyze_nonexistent_file() {
        let migration_system = MigrationSystem::new();
        let result = migration_system.analyze_file(Path::new("/nonexistent/file.shadow"));
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_nonexistent_directory() {
        let migration_system = MigrationSystem::new();
        let result = migration_system.analyze_directory(Path::new("/nonexistent/directory"));
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_empty_directory() {
        use tempfile::TempDir;
        let migration_system = MigrationSystem::new();
        let temp_dir = TempDir::new().unwrap();
        let result = migration_system.analyze_directory(temp_dir.path());
        assert!(result.is_ok());
    }
}