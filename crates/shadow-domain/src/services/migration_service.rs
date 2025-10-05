//! # MigrationService
//!
//! Handles version migrations and compatibility.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use crate::entities::version_matrix::{VersionMatrix, VersionCompatibility, MigrationPath};
use std::path::{Path, PathBuf};
use std::fs;
use std::time::{SystemTime, Duration};

/// Result of a single file migration operation
#[derive(Debug, Clone)]
pub struct MigrationResult {
    pub source_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub target_version: u16,
    pub original_version: u16,
    pub duration: Duration,
    pub bytes_processed: u64,
}

/// Result of a batch migration operation
#[derive(Debug)]
pub struct BatchMigrationResult {
    pub successful: Vec<MigrationResult>,
    pub failed: Vec<(PathBuf, MigrationError)>,
    pub total_duration: Duration,
    pub total_bytes_processed: u64,
}

/// Migration-specific error types
#[derive(Debug, Clone)]
pub enum MigrationError {
    /// Version is not supported for reading
    UnsupportedVersion(u16),
    /// Cannot migrate between these versions
    IncompatibleVersions { from: u16, to: u16 },
    /// No migration path available
    NoMigrationPath { from: u16, to: u16 },
    /// File I/O operation failed
    IoError(String),
    /// Backup operation failed
    BackupFailed(String),
    /// Password required but not provided
    PasswordRequired,
    /// Decryption failed during migration
    DecryptionFailed(String),
    /// Re-encryption failed during migration
    EncryptionFailed(String),
    /// File integrity check failed
    IntegrityCheckFailed,
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationError::UnsupportedVersion(v) => {
                write!(f, "Version {} is not supported for reading", v)
            }
            MigrationError::IncompatibleVersions { from, to } => {
                write!(f, "Cannot migrate from version {} to version {}", from, to)
            }
            MigrationError::NoMigrationPath { from, to } => {
                write!(f, "No migration path available from version {} to version {}", from, to)
            }
            MigrationError::IoError(msg) => {
                write!(f, "File operation failed: {}", msg)
            }
            MigrationError::BackupFailed(msg) => {
                write!(f, "Backup creation failed: {}", msg)
            }
            MigrationError::PasswordRequired => {
                write!(f, "Password required for migration but not provided")
            }
            MigrationError::DecryptionFailed(msg) => {
                write!(f, "Decryption failed during migration: {}", msg)
            }
            MigrationError::EncryptionFailed(msg) => {
                write!(f, "Re-encryption failed during migration: {}", msg)
            }
            MigrationError::IntegrityCheckFailed => {
                write!(f, "File integrity check failed after migration")
            }
        }
    }
}

impl std::error::Error for MigrationError {}

/// Options for controlling migration behavior
#[derive(Debug, Clone)]
pub struct MigrationOptions {
    /// Create backup before migration
    pub create_backup: bool,
    /// Backup file extension (default: ".backup")
    pub backup_extension: String,
    /// Verify integrity after migration
    pub verify_integrity: bool,
    /// Remove backup on successful migration
    pub remove_backup_on_success: bool,
    /// Force migration even if target version is older
    pub force_migration: bool,
}

impl Default for MigrationOptions {
    fn default() -> Self {
        Self {
            create_backup: true,
            backup_extension: ".backup".to_string(),
            verify_integrity: true,
            remove_backup_on_success: false,
            force_migration: false,
        }
    }
}

/// Analysis result for a file's migration status
#[derive(Debug, Clone)]
pub struct FileAnalysis {
    pub file_path: PathBuf,
    pub current_version: u16,
    pub target_version: u16,
    pub compatibility: VersionCompatibility,
    pub migration_required: bool,
    pub can_migrate: bool,
}

/// Handles version migrations and compatibility
pub struct MigrationService {
    version_matrix: VersionMatrix,
}

impl MigrationService {
    /// Create new migration service with Shadow rewrite version matrix
    pub fn new() -> Self {
        Self {
            version_matrix: VersionMatrix::new_shadow_rewrite(),
        }
    }

    /// Create migration service with custom version matrix
    pub fn with_version_matrix(version_matrix: VersionMatrix) -> Self {
        Self { version_matrix }
    }

    /// Check if migration is possible between versions
    pub fn can_migrate(&self, from_version: u16, to_version: u16) -> bool {
        self.version_matrix.can_migrate(from_version, to_version)
    }

    /// Get the version compatibility status
    pub fn get_compatibility(&self, from_version: u16, to_version: u16) -> VersionCompatibility {
        self.version_matrix.is_compatible(from_version, to_version)
    }

    /// Get migration path information
    pub fn get_migration_path(&self, from_version: u16, to_version: u16) -> Option<&MigrationPath> {
        self.version_matrix.get_migration_path(from_version, to_version)
    }

    /// Get current baseline version
    pub fn current_baseline_version(&self) -> u16 {
        self.version_matrix.current_baseline()
    }

    /// Analyze a file to determine its version and migration requirements
    pub fn analyze_file(&self, file_path: &Path) -> Result<FileAnalysis, MigrationError> {
        // For now, this is a placeholder - in real implementation would:
        // 1. Read file header to detect version
        // 2. Check compatibility with current baseline
        // 3. Determine if migration is needed
        
        // Simulated analysis for proof-of-concept
        let file_version = self.detect_file_version(file_path)?;
        let baseline = self.version_matrix.current_baseline();
        let compatibility = self.version_matrix.is_compatible(file_version, baseline);
        let migration_required = matches!(compatibility, VersionCompatibility::RequiresMigration);
        
        Ok(FileAnalysis {
            file_path: file_path.to_path_buf(),
            current_version: file_version,
            target_version: baseline,
            compatibility,
            migration_required,
            can_migrate: self.version_matrix.can_migrate(file_version, baseline),
        })
    }

    /// Migrate a single file to target version
    pub fn migrate_file(
        &self,
        file_path: &Path,
        target_version: u16,
        password: Option<&str>,
        options: &MigrationOptions,
    ) -> Result<MigrationResult, MigrationError> {
        let start_time = SystemTime::now();
        
        // Detect current version
        let current_version = self.detect_file_version(file_path)?;
        
        // Check compatibility
        let compatibility = self.version_matrix.is_compatible(current_version, target_version);
        match compatibility {
            VersionCompatibility::Compatible => {
                // No migration needed
                return Ok(MigrationResult {
                    source_path: file_path.to_path_buf(),
                    backup_path: None,
                    target_version,
                    original_version: current_version,
                    duration: start_time.elapsed().unwrap_or(Duration::ZERO),
                    bytes_processed: self.get_file_size(file_path)?,
                });
            }
            VersionCompatibility::Incompatible => {
                return Err(MigrationError::IncompatibleVersions {
                    from: current_version,
                    to: target_version,
                });
            }
            VersionCompatibility::RequiresMigration => {
                // Proceed with migration
            }
        }

        // Get migration path
        let migration_path = self.version_matrix
            .get_migration_path(current_version, target_version)
            .ok_or(MigrationError::NoMigrationPath {
                from: current_version,
                to: target_version,
            })?;

        // Check password requirement
        if migration_path.requires_password && password.is_none() {
            return Err(MigrationError::PasswordRequired);
        }

        // Create backup if requested
        let backup_path = if options.create_backup {
            Some(self.create_backup(file_path, &options.backup_extension)?)
        } else {
            None
        };

        // Perform migration
        let bytes_processed = match self.perform_migration(
            file_path,
            current_version,
            target_version,
            migration_path,
            password,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Restore from backup on failure
                if let Some(backup) = &backup_path {
                    let _ = self.restore_from_backup(file_path, backup);
                }
                return Err(e);
            }
        };

        // Verify integrity if requested
        if options.verify_integrity {
            if let Err(e) = self.verify_migrated_file(file_path, target_version, password) {
                // Restore from backup on verification failure
                if let Some(backup) = &backup_path {
                    let _ = self.restore_from_backup(file_path, backup);
                }
                return Err(e);
            }
        }

        // Remove backup on success if requested
        if options.remove_backup_on_success {
            if let Some(backup) = &backup_path {
                let _ = fs::remove_file(backup);
            }
        }

        Ok(MigrationResult {
            source_path: file_path.to_path_buf(),
            backup_path,
            target_version,
            original_version: current_version,
            duration: start_time.elapsed().unwrap_or(Duration::ZERO),
            bytes_processed,
        })
    }

    /// Migrate multiple files in a directory
    pub fn migrate_directory(
        &self,
        directory: &Path,
        target_version: u16,
        password: Option<&str>,
        options: &MigrationOptions,
    ) -> Result<BatchMigrationResult, MigrationError> {
        let start_time = SystemTime::now();
        let mut successful = Vec::new();
        let mut failed = Vec::new();
        let mut total_bytes = 0;

        // Find encrypted files in directory
        let encrypted_files = self.find_encrypted_files(directory)?;

        for file_path in encrypted_files {
            match self.migrate_file(&file_path, target_version, password, options) {
                Ok(result) => {
                    total_bytes += result.bytes_processed;
                    successful.push(result);
                }
                Err(error) => {
                    failed.push((file_path, error));
                }
            }
        }

        Ok(BatchMigrationResult {
            successful,
            failed,
            total_duration: start_time.elapsed().unwrap_or(Duration::ZERO),
            total_bytes_processed: total_bytes,
        })
    }

    // Private helper methods

    fn detect_file_version(&self, _file_path: &Path) -> Result<u16, MigrationError> {
        // Placeholder implementation - in real version would read file header
        // For testing, assume legacy V3 files
        Ok(3)
    }

    fn get_file_size(&self, file_path: &Path) -> Result<u64, MigrationError> {
        fs::metadata(file_path)
            .map(|m| m.len())
            .map_err(|e| MigrationError::IoError(e.to_string()))
    }

    fn create_backup(&self, file_path: &Path, extension: &str) -> Result<PathBuf, MigrationError> {
        let mut backup_path = file_path.to_path_buf();
        backup_path.set_extension(
            format!("{}{}", 
                file_path.extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or(""),
                extension
            )
        );

        fs::copy(file_path, &backup_path)
            .map_err(|e| MigrationError::BackupFailed(e.to_string()))?;

        Ok(backup_path)
    }

    fn restore_from_backup(&self, original_path: &Path, backup_path: &Path) -> Result<(), MigrationError> {
        fs::copy(backup_path, original_path)
            .map_err(|e| MigrationError::IoError(e.to_string()))?;
        Ok(())
    }

    fn perform_migration(
        &self,
        _file_path: &Path,
        _from_version: u16,
        _to_version: u16,
        _migration_path: &MigrationPath,
        _password: Option<&str>,
    ) -> Result<u64, MigrationError> {
        // Placeholder implementation - in real version would:
        // 1. Read and decrypt file with old format
        // 2. Re-encrypt with new format
        // 3. Write to same path atomically
        
        // For testing, simulate successful migration
        Ok(1024) // Simulated bytes processed
    }

    fn verify_migrated_file(
        &self,
        _file_path: &Path,
        _expected_version: u16,
        _password: Option<&str>,
    ) -> Result<(), MigrationError> {
        // Placeholder implementation - in real version would:
        // 1. Read file header to verify version
        // 2. Attempt decryption to verify integrity
        
        // For testing, assume verification passes
        Ok(())
    }

    fn find_encrypted_files(&self, _directory: &Path) -> Result<Vec<PathBuf>, MigrationError> {
        // Placeholder implementation - in real version would scan directory
        // for files with encrypted file headers
        
        // For testing, return empty list
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_migration_service_creation() {
        let service = MigrationService::new();
        assert_eq!(service.current_baseline_version(), 1);
    }

    #[test]
    fn test_compatibility_checking() {
        let service = MigrationService::new();
        
        // V1 ↔ V1 compatible
        assert_eq!(
            service.get_compatibility(1, 1),
            VersionCompatibility::Compatible
        );
        
        // V3 → V1 requires migration
        assert_eq!(
            service.get_compatibility(3, 1),
            VersionCompatibility::RequiresMigration
        );
        
        // V1 → V3 incompatible
        assert_eq!(
            service.get_compatibility(1, 3),
            VersionCompatibility::Incompatible
        );
    }

    #[test]
    fn test_migration_path_retrieval() {
        let service = MigrationService::new();
        
        // V3 → V1 should have migration path
        let path = service.get_migration_path(3, 1);
        assert!(path.is_some());
        
        let path = path.unwrap();
        assert_eq!(path.from_version, 3);
        assert_eq!(path.to_version, 1);
        assert!(path.requires_password);
        assert!(!path.is_reversible);
        
        // V1 → V3 should not have migration path
        assert!(service.get_migration_path(1, 3).is_none());
    }

    #[test]
    fn test_migration_options_defaults() {
        let options = MigrationOptions::default();
        assert!(options.create_backup);
        assert_eq!(options.backup_extension, ".backup");
        assert!(options.verify_integrity);
        assert!(!options.remove_backup_on_success);
        assert!(!options.force_migration);
    }

    #[test]
    fn test_file_analysis_placeholder() {
        let service = MigrationService::new();
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.enc");
        
        // Create a dummy file
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"dummy encrypted content").unwrap();
        
        let analysis = service.analyze_file(&file_path).unwrap();
        
        assert_eq!(analysis.file_path, file_path);
        assert_eq!(analysis.current_version, 3); // Placeholder assumes V3
        assert_eq!(analysis.target_version, 1);  // Current baseline
        assert_eq!(analysis.compatibility, VersionCompatibility::RequiresMigration);
        assert!(analysis.migration_required);
        assert!(analysis.can_migrate);
    }
}