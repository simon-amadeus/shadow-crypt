//! File migration functionality
//! 
//! This module provides comprehensive file migration capabilities for upgrading
//! between different versions of the Shadow encryption format. It implements the
//! core migration logic used by the `shadowmigrate` binary for safe format updates.
//! 
//! # Features
//! 
//! - **Version detection** and compatibility analysis for encrypted files
//! - **Migration planning** with safety checks and rollback strategies
//! - **Safe migration execution** with backup creation and verification
//! - **Batch processing** for migrating multiple files efficiently
//! - **Progress reporting** for long-running migration operations
//! 
//! # Architecture
//! 
//! This module follows the standard Shadow use case pattern:
//! - `file_analyzer.rs` - Version detection and file analysis
//! - `migration_planner.rs` - Migration strategy planning and validation
//! - `safety_checker.rs` - Safety verification and backup management
//! - `cli.rs` - Command-line interface and argument parsing
//! 
//! # Example Usage
//! 
//! ```rust,no_run
//! use shadow_crypt::migration::{analyze_shadow_file, create_migration_plan};
//! use std::path::Path;
//! 
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let file = Path::new("old_format.shadow");
//! let analysis = analyze_shadow_file(file)?;
//! 
//! if analysis.needs_migration() {
//!     let plan = create_migration_plan(&analysis)?;
//!     // Execute migration with plan...
//! }
//! # Ok(())
//! # }
//! ```
//! 
//! # Security
//! 
//! Migration operations provide:
//! - Automatic backup creation before any modification
//! - Verification of file integrity throughout the migration process
//! - Rollback capabilities if migration fails at any stage
//! - Preservation of all original metadata and permissions
//! - Safe handling of multiple encryption algorithm transitions

pub mod cli;
pub mod file_analyzer;
pub mod migration_planner;
pub mod safety_checker;

// Re-export main functionality for the binary
pub use cli::run_migration_cli;
pub use file_analyzer::analyze_shadow_file;
pub use migration_planner::{MigrationPlan, create_migration_plan};
pub use safety_checker::{SafetyCheck, verify_migration_safety};