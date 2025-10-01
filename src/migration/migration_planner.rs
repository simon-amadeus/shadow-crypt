//! Migration planning functionality
//! 
//! Creates detailed migration plans for Shadow file format upgrades.

use crate::shared::{CryptoError, algorithms::CURRENT_VERSION};
use crate::shared::version_dispatch::VersionMigrator;
use crate::migration::file_analyzer::FileAnalysis;
use crate::migration::safety_checker::SafetyCheck;
use std::path::PathBuf;

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

/// Migration planner configuration
#[derive(Debug, Clone)]
pub struct MigrationPlanner {
    pub create_backups: bool,
    pub verify_after_migration: bool,
    pub batch_size: usize,
}

impl MigrationPlanner {
    /// Create new migration planner with default settings
    pub fn new() -> Self {
        Self {
            create_backups: true,
            verify_after_migration: true,
            batch_size: 100,
        }
    }
    
    /// Create migration planner with custom settings
    pub fn with_settings(create_backups: bool, verify_after_migration: bool, batch_size: usize) -> Self {
        Self {
            create_backups,
            verify_after_migration,
            batch_size,
        }
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
}

impl Default for MigrationPlanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Create migration plan from file analysis
pub fn create_migration_plan(analysis: &FileAnalysis) -> Result<MigrationPlan, CryptoError> {
    let planner = MigrationPlanner::new();
    
    // Check if migration is actually needed
    if analysis.version_info.is_current {
        return Err(CryptoError::HeaderParsingError(
            format!("File {} is already current version {}", 
                   analysis.file_path.display(), 
                   analysis.version_info.current)
        ));
    }
    
    // Check if migration is possible using new versioning system
    if !VersionMigrator::can_migrate(analysis.version_info.current, CURRENT_VERSION) {
        return Err(CryptoError::HeaderParsingError(
            format!("Cannot migrate file {} from version {} to version {}", 
                   analysis.file_path.display(),
                   analysis.version_info.current,
                   CURRENT_VERSION)
        ));
    }
    
    let plan = MigrationPlan {
        source_path: analysis.file_path.clone(),
        source_version: analysis.version_info.current,
        target_version: CURRENT_VERSION,
        requires_backup: planner.create_backups,
        estimated_steps: planner.estimate_migration_steps(analysis.version_info.current, CURRENT_VERSION),
        safety_checks: planner.get_required_safety_checks(),
    };
    
    Ok(plan)
}

/// Create migration plans for multiple files
pub fn create_batch_migration_plan(analyses: &[FileAnalysis]) -> Result<Vec<MigrationPlan>, CryptoError> {
    let mut plans = Vec::new();
    
    for analysis in analyses {
        if analysis.version_info.needs_migration {
            match create_migration_plan(analysis) {
                Ok(plan) => plans.push(plan),
                Err(e) => {
                    eprintln!("Warning: Could not create migration plan for {}: {}", 
                             analysis.file_path.display(), e);
                }
            }
        }
    }
    
    Ok(plans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::VersionInfo;
    use std::path::Path;
    
    #[test]
    fn test_migration_planner_creation() {
        let planner = MigrationPlanner::new();
        assert!(planner.create_backups);
        assert!(planner.verify_after_migration);
        assert_eq!(planner.batch_size, 100);
    }
    
    #[test]
    fn test_migration_planner_custom_settings() {
        let planner = MigrationPlanner::with_settings(false, false, 50);
        assert!(!planner.create_backups);
        assert!(!planner.verify_after_migration);
        assert_eq!(planner.batch_size, 50);
    }
    
    #[test]
    fn test_estimate_migration_steps() {
        let planner = MigrationPlanner::new();
        let steps = planner.estimate_migration_steps(1, 1);
        // Same version: base(3) + backup(2) + verification(1) + version_diff(0) = 6
        assert_eq!(steps, 6);
    }
    
    #[test]
    fn test_create_migration_plan_current_version() {
        let analysis = FileAnalysis {
            file_path: Path::new("/test/file.shadow").to_path_buf(),
            version_info: VersionInfo {
                current: 1,
                min_supported: 1,
                max_supported: 1,
                is_current: true,
                is_supported: true,
                needs_migration: false,
                can_migrate: true,
            },
            file_size: 1000,
            is_shadow_file: true,
            header_valid: true,
        };
        
        let result = create_migration_plan(&analysis);
        assert!(result.is_err());
    }
}