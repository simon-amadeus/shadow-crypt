//! # Shadowmigrate CLI Binary
//!
//! Migration tool for updating encrypted files with outdated header versions to the latest format.

use clap::Parser;
use std::path::PathBuf;
use std::process;

// Import from the shadow-crypt library
use shadow_crypt::application::workflows::migration_workflow::{MigrationWorkflow, MigrationWorkflowError};
use shadow_crypt::application::workflows::WorkflowResult;
use shadow_crypt::infrastructure::{StandardFileRepository, StandardPasswordRepository};
use shadow_crypt::cli::common::{CLIValidator, CLIFormatter};

/// Shadowmigrate File Format Migration Tool
#[derive(Parser, Debug)]
#[command(name = "shadowmigrate")]
#[command(about = "Migration tool for updating encrypted file format versions")]
#[command(long_about = "Identify and migrate encrypted files with outdated header versions to the latest format")]
struct ShadowmigrateArgs {
    /// File or directory to migrate (default: current directory)
    input: Option<PathBuf>,
}

impl ShadowmigrateArgs {
    /// Convert input to a vector of patterns for the workflow
    fn get_input_patterns(&self) -> Vec<String> {
        match &self.input {
            Some(path) => vec![path.to_string_lossy().to_string()],
            None => vec![".".to_string()], // Current directory
        }
    }
    
    /// Validate that the input path exists if specified
    fn validate_input(&self) -> Result<(), String> {
        if let Some(path) = &self.input {
            CLIValidator::validate_input_path(path)?;
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ShadowmigrateArgs::parse();
    
    // Validate arguments
    if let Err(msg) = args.validate_input() {
        CLIFormatter::print_error_and_exit(&msg);
    }
    
    let input_patterns = args.get_input_patterns();
    
    println!("Shadowmigrate File Format Migration Tool");
    println!("Analyzing: {:?}", input_patterns);
    
    // Create repository instances
    let file_repo = Box::new(StandardFileRepository::new());
    let password_repo = Box::new(StandardPasswordRepository::new());
    
    // Create migration workflow
    let mut workflow = MigrationWorkflow::new(file_repo, password_repo);
    
    // Execute migration workflow with target version (use latest version)
    const TARGET_VERSION: u16 = 1; // Current latest version is V1
    
    match workflow.execute(input_patterns, TARGET_VERSION) {
        Ok(WorkflowResult::Migration(migration_result)) => {
            // Print user-friendly results
            println!("\n🔄 Migration Analysis Complete!");
            
            if migration_result.migration_steps.is_empty() {
                println!("✅ All files are already up-to-date");
                println!("   No migration required for any files found");
            } else {
                println!("📋 Migration Plan:");
                println!("✅ Files analyzed: {}", migration_result.files_to_migrate.len());
                println!("🔄 Files requiring migration: {}", migration_result.migration_steps.len());
                
                // Print migration details
                for migration_step in &migration_result.migration_steps {
                    let status = if migration_step.required { "Required" } else { "Optional" };
                    println!("   {} {} → Version {} to {}",
                        status,
                        migration_step.file_path.display(),
                        migration_step.from_version,
                        migration_step.to_version
                    );
                }
                
                // Note: In a complete implementation, here we would:
                // 1. Ask for user confirmation
                // 2. Execute the migration steps
                // 3. Report success/failure for each file
                println!("\n⚠️  Migration execution not yet implemented");
                println!("   This tool currently provides analysis only");
            }
            
            println!("⏱️  Estimated migration time: {:?}", migration_result.estimated_duration);
        }
        Ok(_other_result) => {
            eprintln!("Error: Unexpected workflow result type");
            process::exit(1);
        }
        Err(MigrationWorkflowError::PasswordInput(_)) => {
            // User cancelled password input
            CLIFormatter::print_cancelled_and_exit();
        }
        Err(e) => {
            eprintln!("Migration analysis failed: {}", e);
            process::exit(1);
        }
    }
    
    Ok(())
}