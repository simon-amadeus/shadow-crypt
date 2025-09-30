//! Migration module for shadowmigrate binary
//! 
//! This module contains all migration-specific functionality following the
//! vertical slicing architecture pattern used throughout the codebase.

pub mod cli;
pub mod file_analyzer;
pub mod migration_planner;
pub mod safety_checker;

// Re-export main functionality for the binary
pub use cli::run_migration_cli;
pub use file_analyzer::analyze_shadow_file;
pub use migration_planner::{MigrationPlan, create_migration_plan};
pub use safety_checker::{SafetyCheck, verify_migration_safety};