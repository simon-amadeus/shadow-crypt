//! Integration tests for migration system
//! 
//! These tests verify that the migration system foundation is working correctly
//! and ready for future format versions.

use shadow_crypt::shared::{VersionInfo, CURRENT_VERSION};
use shadow_crypt::migration::migration_planner::{MigrationPlan, MigrationPlanner};
use shadow_crypt::migration::file_analyzer::{analyze_shadow_file, analyze_directory};
use shadow_crypt::migration::safety_checker::{SafetyCheck, verify_migration_safety};
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_migration_planner_basic_functionality() {
    let migration_planner = MigrationPlanner::new();
    
    // Test that the migration planner can be created with default settings
    assert!(migration_planner.create_backups);
    assert!(migration_planner.verify_after_migration);
    assert_eq!(migration_planner.batch_size, 100);
}

#[test]
fn test_migration_planner_custom_settings() {
    let migration_planner = MigrationPlanner::with_settings(false, false, 50);
    
    // Test custom settings
    assert!(!migration_planner.create_backups);
    assert!(!migration_planner.verify_after_migration);
    assert_eq!(migration_planner.batch_size, 50);
}

#[test]
fn test_analyze_empty_directory() {
    let temp_dir = TempDir::new().unwrap();
    
    // Test analyzing an empty directory
    let result = analyze_directory(temp_dir.path());
    assert!(result.is_ok());
    
    let analyses = result.unwrap();
    assert!(analyses.is_empty());
}

#[test]
fn test_analyze_nonexistent_file() {
    // Test analyzing a file that doesn't exist
    let result = analyze_shadow_file(Path::new("/nonexistent/file.shadow"));
    assert!(result.is_err());
}

#[test]
fn test_analyze_nonexistent_directory() {
    // Test analyzing a directory that doesn't exist
    let result = analyze_directory(Path::new("/nonexistent/directory"));
    assert!(result.is_err());
}

#[test]
fn test_version_constants() {
    // Test that version constants are properly defined
    assert_eq!(CURRENT_VERSION, 1);
}

#[test]
fn test_version_info_structure() {
    // Test the VersionInfo structure
    let version_info = VersionInfo {
        current: 1,
        min_supported: 1,
        max_supported: 1,
        is_current: true,
        is_supported: true,
        needs_migration: false,
        can_migrate: true,
    };
    
    assert_eq!(version_info.current, 1);
    assert!(version_info.is_current);
    assert!(version_info.is_supported);
    assert!(!version_info.needs_migration);
    assert!(version_info.can_migrate);
}

#[test]
fn test_safety_verification() {
    // Create a dummy migration plan
    let plan = MigrationPlan {
        source_path: Path::new("/dummy").to_path_buf(),
        source_version: 1,
        target_version: 1,
        requires_backup: true,
        estimated_steps: 5,
        safety_checks: vec![SafetyCheck::VerifyFileIntegrity],
    };
    
    // Test that safety verification works (should fail for non-existent file)
    let result = verify_migration_safety(&plan);
    assert!(result.is_ok());
    
    let safety_report = result.unwrap();
    assert!(!safety_report.safe_to_proceed);
    assert_eq!(safety_report.checks_failed, 1);
}

#[test]
fn test_safety_checks_enum() {
    // Test that safety checks can be compared
    let check1 = SafetyCheck::VerifyFileIntegrity;
    let check2 = SafetyCheck::VerifyFileIntegrity;
    assert_eq!(check1, check2);
    
    let check3 = SafetyCheck::CreateBackup;
    assert_ne!(check1, check3);
}