use shadow_crypt::domain::entities::version_matrix::{
    VersionMatrix, VersionCompatibility, MigrationType
};
use shadow_crypt::domain::services::migration_service::{
    MigrationService, MigrationOptions, MigrationError
};
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

/// Test comprehensive version compatibility scenarios
#[test]
fn test_version_compatibility_matrix() {
    let matrix = VersionMatrix::new_shadow_rewrite();
    
    // Test all defined compatibility relationships
    let test_cases = vec![
        // (from, to, expected)
        (1, 1, VersionCompatibility::Compatible),
        (3, 1, VersionCompatibility::RequiresMigration),
        (1, 3, VersionCompatibility::Incompatible),
        (99, 1, VersionCompatibility::Incompatible),
        (1, 99, VersionCompatibility::Incompatible),
    ];
    
    for (from, to, expected) in test_cases {
        assert_eq!(
            matrix.is_compatible(from, to),
            expected,
            "Failed compatibility check for {} -> {}",
            from, to
        );
    }
}

/// Test version read/write capabilities
#[test]
fn test_version_read_write_capabilities() {
    let matrix = VersionMatrix::new_shadow_rewrite();
    
    // V1 (baseline): can read and write
    assert!(matrix.can_read(1));
    assert!(matrix.can_write(1));
    
    // V3 (legacy): can read but cannot write
    assert!(matrix.can_read(3));
    assert!(!matrix.can_write(3));
    
    // Unknown versions: cannot read or write
    assert!(!matrix.can_read(99));
    assert!(!matrix.can_write(99));
}

/// Test migration path configurations
#[test]
fn test_migration_paths() {
    let matrix = VersionMatrix::new_shadow_rewrite();
    
    // V3 -> V1: Should have migration path
    let path = matrix.get_migration_path(3, 1).expect("V3->V1 migration path should exist");
    assert_eq!(path.from_version, 3);
    assert_eq!(path.to_version, 1);
    assert_eq!(path.migration_type, MigrationType::HeaderMigration);
    assert!(path.requires_password);
    assert!(!path.is_reversible);
    
    // V1 -> V3: Should not have migration path
    assert!(matrix.get_migration_path(1, 3).is_none());
    
    // V1 -> V1: No migration path needed (compatible)
    assert!(matrix.get_migration_path(1, 1).is_none());
}

/// Test migration service integration with version matrix
#[test]
fn test_migration_service_integration() {
    let service = MigrationService::new();
    
    // Test basic service configuration
    assert_eq!(service.current_baseline_version(), 1);
    
    // Test migration capability checks
    assert!(service.can_migrate(3, 1)); // Legacy to baseline
    assert!(service.can_migrate(1, 1)); // Baseline to baseline (no-op)
    assert!(!service.can_migrate(1, 3)); // No reverse migration
    assert!(!service.can_migrate(99, 1)); // Unknown version
    
    // Test compatibility status
    assert_eq!(
        service.get_compatibility(3, 1),
        VersionCompatibility::RequiresMigration
    );
    assert_eq!(
        service.get_compatibility(1, 1),
        VersionCompatibility::Compatible
    );
    assert_eq!(
        service.get_compatibility(1, 3),
        VersionCompatibility::Incompatible
    );
}

/// Test file analysis functionality
#[test]
fn test_file_analysis() {
    let service = MigrationService::new();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.enc");
    
    // Create a test file
    let mut file = File::create(&test_file).unwrap();
    file.write_all(b"test encrypted content").unwrap();
    
    let analysis = service.analyze_file(&test_file).unwrap();
    
    // Verify analysis results (placeholder assumes V3 legacy file)
    assert_eq!(analysis.current_version, 3);
    assert_eq!(analysis.target_version, 1);
    assert_eq!(analysis.compatibility, VersionCompatibility::RequiresMigration);
    assert!(analysis.migration_required);
    assert!(analysis.can_migrate);
    assert_eq!(analysis.file_path, test_file);
}

/// Test migration options configuration
#[test]
fn test_migration_options() {
    let default_options = MigrationOptions::default();
    assert!(default_options.create_backup);
    assert_eq!(default_options.backup_extension, ".backup");
    assert!(default_options.verify_integrity);
    assert!(!default_options.remove_backup_on_success);
    assert!(!default_options.force_migration);
    
    // Test custom options
    let custom_options = MigrationOptions {
        create_backup: false,
        backup_extension: ".bak".to_string(),
        verify_integrity: false,
        remove_backup_on_success: true,
        force_migration: true,
    };
    
    assert!(!custom_options.create_backup);
    assert_eq!(custom_options.backup_extension, ".bak");
    assert!(!custom_options.verify_integrity);
    assert!(custom_options.remove_backup_on_success);
    assert!(custom_options.force_migration);
}

/// Test error handling scenarios
#[test]
fn test_migration_error_handling() {
    // Test error display formatting
    let errors = vec![
        MigrationError::UnsupportedVersion(99),
        MigrationError::IncompatibleVersions { from: 1, to: 3 },
        MigrationError::NoMigrationPath { from: 1, to: 3 },
        MigrationError::IoError("File not found".to_string()),
        MigrationError::BackupFailed("Permission denied".to_string()),
        MigrationError::PasswordRequired,
        MigrationError::DecryptionFailed("Invalid key".to_string()),
        MigrationError::EncryptionFailed("Crypto error".to_string()),
        MigrationError::IntegrityCheckFailed,
    ];
    
    for error in errors {
        let error_string = error.to_string();
        assert!(!error_string.is_empty());
        assert!(!error_string.contains("Debug")); // Should be user-friendly
    }
}

/// Test baseline version consistency
#[test]
fn test_baseline_version_consistency() {
    let matrix = VersionMatrix::new_shadow_rewrite();
    let service = MigrationService::new();
    
    // Both should agree on baseline version
    assert_eq!(matrix.current_baseline(), service.current_baseline_version());
    assert_eq!(matrix.current_baseline(), 1);
    
    // Baseline should be readable and writable
    assert!(matrix.can_read(matrix.current_baseline()));
    assert!(matrix.can_write(matrix.current_baseline()));
}

/// Test future extensibility scenarios
#[test]
fn test_future_version_scenarios() {
    let matrix = VersionMatrix::new_shadow_rewrite();
    
    // Future versions should be incompatible until explicitly added
    let future_versions = [2, 4, 5, 10, 100];
    let current_baseline = matrix.current_baseline();
    
    for future_version in future_versions {
        // Cannot read/write future versions
        assert!(!matrix.can_read(future_version));
        assert!(!matrix.can_write(future_version));
        
        // No compatibility with future versions
        assert_eq!(
            matrix.is_compatible(current_baseline, future_version),
            VersionCompatibility::Incompatible
        );
        assert_eq!(
            matrix.is_compatible(future_version, current_baseline),
            VersionCompatibility::Incompatible
        );
        
        // No migration paths to/from future versions
        assert!(matrix.get_migration_path(current_baseline, future_version).is_none());
        assert!(matrix.get_migration_path(future_version, current_baseline).is_none());
    }
}

/// Test version matrix immutability expectations
#[test]
fn test_version_matrix_immutability() {
    let matrix1 = VersionMatrix::new_shadow_rewrite();
    let matrix2 = VersionMatrix::new_shadow_rewrite();
    
    // Multiple instances should be consistent
    assert_eq!(matrix1.current_baseline(), matrix2.current_baseline());
    assert_eq!(matrix1.readable_versions(), matrix2.readable_versions());
    assert_eq!(matrix1.writable_versions(), matrix2.writable_versions());
    
    // Test specific version capabilities are identical
    let test_versions = [1, 3, 99];
    for version in test_versions {
        assert_eq!(matrix1.can_read(version), matrix2.can_read(version));
        assert_eq!(matrix1.can_write(version), matrix2.can_write(version));
    }
}