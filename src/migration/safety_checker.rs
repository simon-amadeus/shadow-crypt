//! Safety checking functionality for migration operations
//! 
//! Provides comprehensive safety verification before migration execution.

use crate::shared::CryptoError;
use crate::migration::migration_planner::MigrationPlan;
use std::fs;

/// Safety checks to perform before migration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyCheck {
    VerifyFileIntegrity,
    CheckDiskSpace,
    ValidatePermissions,
    TestDecryption,
    CreateBackup,
}

/// Safety verification report
#[derive(Debug, Clone)]
pub struct SafetyReport {
    pub checks_passed: usize,
    pub checks_failed: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub safe_to_proceed: bool,
}

/// Verify migration safety for a single file
pub fn verify_migration_safety(plan: &MigrationPlan) -> Result<SafetyReport, CryptoError> {
    let mut report = SafetyReport {
        checks_passed: 0,
        checks_failed: 0,
        warnings: Vec::new(),
        errors: Vec::new(),
        safe_to_proceed: true,
    };
    
    for check in &plan.safety_checks {
        match perform_safety_check(check, plan) {
            Ok(result) => {
                if result.passed {
                    report.checks_passed += 1;
                    if let Some(warning) = result.warning {
                        report.warnings.push(warning);
                    }
                } else {
                    report.checks_failed += 1;
                    report.safe_to_proceed = false;
                    if let Some(error) = result.error {
                        report.errors.push(error);
                    }
                }
            }
            Err(e) => {
                report.checks_failed += 1;
                report.safe_to_proceed = false;
                report.errors.push(format!("Safety check {:?} failed: {}", check, e));
            }
        }
    }
    
    Ok(report)
}

/// Result of a single safety check
#[derive(Debug)]
struct SafetyCheckResult {
    passed: bool,
    warning: Option<String>,
    error: Option<String>,
}

/// Perform a specific safety check
fn perform_safety_check(check: &SafetyCheck, plan: &MigrationPlan) -> Result<SafetyCheckResult, CryptoError> {
    match check {
        SafetyCheck::VerifyFileIntegrity => verify_file_integrity(plan),
        SafetyCheck::CheckDiskSpace => check_disk_space(plan),
        SafetyCheck::ValidatePermissions => validate_permissions(plan),
        SafetyCheck::TestDecryption => test_decryption(plan),
        SafetyCheck::CreateBackup => check_backup_feasibility(plan),
    }
}

/// Verify file integrity before migration
fn verify_file_integrity(plan: &MigrationPlan) -> Result<SafetyCheckResult, CryptoError> {
    // Check if file exists and is readable
    if !plan.source_path.exists() {
        return Ok(SafetyCheckResult {
            passed: false,
            warning: None,
            error: Some(format!("File does not exist: {}", plan.source_path.display())),
        });
    }
    
    // Try to read file metadata
    match fs::metadata(&plan.source_path) {
        Ok(metadata) => {
            if metadata.len() == 0 {
                Ok(SafetyCheckResult {
                    passed: false,
                    warning: None,
                    error: Some("File is empty".to_string()),
                })
            } else {
                Ok(SafetyCheckResult {
                    passed: true,
                    warning: None,
                    error: None,
                })
            }
        }
        Err(e) => Ok(SafetyCheckResult {
            passed: false,
            warning: None,
            error: Some(format!("Cannot access file metadata: {}", e)),
        })
    }
}

/// Check available disk space for migration
fn check_disk_space(plan: &MigrationPlan) -> Result<SafetyCheckResult, CryptoError> {
    // For now, just check that we can read the file size
    match fs::metadata(&plan.source_path) {
        Ok(metadata) => {
            let file_size = metadata.len();
            
            // Estimate space needed: original + backup + new version
            let estimated_space_needed = if plan.requires_backup {
                file_size * 3 // Original + backup + new
            } else {
                file_size * 2 // Original + new
            };
            
            // This is a simplified check - in a real implementation,
            // we would check actual available disk space
            if estimated_space_needed > 1_000_000_000 { // 1GB
                Ok(SafetyCheckResult {
                    passed: true,
                    warning: Some(format!("Large file migration may require {}GB disk space", 
                                        estimated_space_needed / 1_000_000_000)),
                    error: None,
                })
            } else {
                Ok(SafetyCheckResult {
                    passed: true,
                    warning: None,
                    error: None,
                })
            }
        }
        Err(e) => Ok(SafetyCheckResult {
            passed: false,
            warning: None,
            error: Some(format!("Cannot check file size: {}", e)),
        })
    }
}

/// Validate file permissions for migration
fn validate_permissions(plan: &MigrationPlan) -> Result<SafetyCheckResult, CryptoError> {
    // Check if file is readable and writable
    match fs::metadata(&plan.source_path) {
        Ok(metadata) => {
            let permissions = metadata.permissions();
            
            // On Unix-like systems, check if we can read and write
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = permissions.mode();
                let owner_can_read = (mode & 0o400) != 0;
                let owner_can_write = (mode & 0o200) != 0;
                
                if !owner_can_read {
                    return Ok(SafetyCheckResult {
                        passed: false,
                        warning: None,
                        error: Some("File is not readable".to_string()),
                    });
                }
                
                if !owner_can_write {
                    return Ok(SafetyCheckResult {
                        passed: true,
                        warning: Some("File is read-only - may need to change permissions for migration".to_string()),
                        error: None,
                    });
                }
            }
            
            Ok(SafetyCheckResult {
                passed: true,
                warning: None,
                error: None,
            })
        }
        Err(e) => Ok(SafetyCheckResult {
            passed: false,
            warning: None,
            error: Some(format!("Cannot check file permissions: {}", e)),
        })
    }
}

/// Test decryption before migration (placeholder)
fn test_decryption(_plan: &MigrationPlan) -> Result<SafetyCheckResult, CryptoError> {
    // This would test actual decryption in a real implementation
    // For now, just report that this check is not yet implemented
    Ok(SafetyCheckResult {
        passed: true,
        warning: Some("Decryption test not yet implemented".to_string()),
        error: None,
    })
}

/// Check backup creation feasibility
fn check_backup_feasibility(plan: &MigrationPlan) -> Result<SafetyCheckResult, CryptoError> {
    if !plan.requires_backup {
        return Ok(SafetyCheckResult {
            passed: true,
            warning: None,
            error: None,
        });
    }
    
    // Check if backup location would be writable
    let backup_path = plan.source_path.with_extension("shadow.backup");
    
    if backup_path.exists() {
        Ok(SafetyCheckResult {
            passed: true,
            warning: Some(format!("Backup file {} already exists", backup_path.display())),
            error: None,
        })
    } else {
        // Check if we can write to the directory
        let parent = plan.source_path.parent().unwrap_or_else(|| std::path::Path::new("."));
        match fs::metadata(parent) {
            Ok(_) => Ok(SafetyCheckResult {
                passed: true,
                warning: None,
                error: None,
            }),
            Err(e) => Ok(SafetyCheckResult {
                passed: false,
                warning: None,
                error: Some(format!("Cannot access backup directory: {}", e)),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    
    #[test]
    fn test_safety_check_equality() {
        let check1 = SafetyCheck::VerifyFileIntegrity;
        let check2 = SafetyCheck::VerifyFileIntegrity;
        assert_eq!(check1, check2);
    }
    
    #[test]
    fn test_safety_report_creation() {
        let report = SafetyReport {
            checks_passed: 3,
            checks_failed: 1,
            warnings: vec!["Warning message".to_string()],
            errors: vec!["Error message".to_string()],
            safe_to_proceed: false,
        };
        
        assert_eq!(report.checks_passed, 3);
        assert_eq!(report.checks_failed, 1);
        assert!(!report.safe_to_proceed);
    }
    
    #[test]
    fn test_verify_nonexistent_file() {
        let plan = MigrationPlan {
            source_path: Path::new("/nonexistent/file.shadow").to_path_buf(),
            source_version: 1,
            target_version: 1,
            requires_backup: false,
            estimated_steps: 5,
            safety_checks: vec![SafetyCheck::VerifyFileIntegrity],
        };
        
        let result = verify_migration_safety(&plan).unwrap();
        assert!(!result.safe_to_proceed);
        assert_eq!(result.checks_failed, 1);
    }
}