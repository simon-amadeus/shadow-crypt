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
    
    /// Execute migration without confirmation prompt
    #[arg(short = 'y', long = "yes")]
    auto_confirm: bool,
    
    /// Only show analysis without executing migration
    #[arg(short = 'n', long = "dry-run")]
    dry_run: bool,
}

impl ShadowmigrateArgs {
    /// Convert input to a vector of patterns for the workflow
    fn get_input_patterns(&self) -> Vec<String> {
        match &self.input {
            Some(path) => vec![path.to_string_lossy().to_string()],
            None => vec![".".to_string()], // Current directory
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ShadowmigrateArgs::parse();
    
    // Validate arguments if a specific file/directory is provided
    if let Some(path) = &args.input {
        if let Err(msg) = CLIValidator::validate_input_path(path) {
            CLIFormatter::print_error_and_exit(&msg);
        }
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
            // Print analysis results
            println!("\n🔄 Migration Analysis Complete!");
            
            if migration_result.migration_steps.is_empty() {
                println!("✅ All files are already up-to-date");
                println!("   No migration required for any files found");
                println!("⏱️  Analysis time: {:?}", migration_result.estimated_duration);
                return Ok(());
            }
            
            // Print migration plan
            println!("📋 Migration Plan:");
            println!("✅ Files analyzed: {}", migration_result.files_to_migrate.len());
            println!("🔄 Files requiring migration: {}", migration_result.migration_steps.len());
            
            for migration_step in &migration_result.migration_steps {
                let status = if migration_step.required { "Required" } else { "Optional" };
                println!("   {} {} → Version {} to {}",
                    status,
                    migration_step.file_path.display(),
                    migration_step.from_version,
                    migration_step.to_version
                );
            }
            
            println!("⏱️  Estimated migration time: {:?}", migration_result.estimated_duration);
            
            // Check if this is a dry run
            if args.dry_run {
                println!("\n🔍 Dry run complete - no files were modified");
                return Ok(());
            }
            
            // Ask for user confirmation unless auto-confirmed
            if !args.auto_confirm {
                println!("\n⚠️  Migration will modify your files (backups will be created)");
                print!("Proceed with migration? [y/N]: ");
                use std::io::{self, Write};
                io::stdout().flush().unwrap();
                
                let mut response = String::new();
                io::stdin().read_line(&mut response).unwrap();
                let response = response.trim().to_lowercase();
                
                if response != "y" && response != "yes" {
                    println!("Migration cancelled by user");
                    return Ok(());
                }
            }
            
            // Execute migration for each file
            println!("\n🔄 Executing migration...");
            let mut successful_migrations = 0;
            let mut failed_migrations = 0;
            let total_migrations = migration_result.migration_steps.iter()
                .filter(|step| step.required).count();
            
            for (index, migration_step) in migration_result.migration_steps.iter().enumerate() {
                if !migration_step.required {
                    continue; // Skip optional migrations for now
                }
                
                print!("Migrating {} [{}/{}]... ", 
                    migration_step.file_path.file_name()
                        .unwrap_or_default().to_string_lossy(),
                    successful_migrations + failed_migrations + 1,
                    total_migrations
                );
                use std::io::Write;
                std::io::stdout().flush().unwrap();
                
                match workflow.migrate_file(&migration_step.file_path, migration_step.to_version) {
                    Ok(result_msg) => {
                        println!("✅ Success");
                        if index == migration_result.migration_steps.len() - 1 {
                            println!("   {}", result_msg);
                        }
                        successful_migrations += 1;
                    }
                    Err(e) => {
                        println!("❌ Failed: {}", e);
                        failed_migrations += 1;
                    }
                }
            }
            
            // Print final summary
            println!("\n📊 Migration Summary:");
            println!("✅ Successful: {}", successful_migrations);
            if failed_migrations > 0 {
                println!("❌ Failed: {}", failed_migrations);
            }
            
            if failed_migrations == 0 {
                println!("🎉 All migrations completed successfully!");
            } else {
                println!("⚠️  Some migrations failed - check error messages above");
                process::exit(1);
            }
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