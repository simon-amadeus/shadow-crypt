use colored::Colorize;

use crate::{
    encryption::output::EncryptionReport,
    errors::{WorkflowError, WorkflowResult},
};

/// Display simple progress for file operations
pub fn display_progress(current: u64, total: u64) {
    if total == 0 {
        return;
    }

    println!("Processing file {} of {}", current, total);
}

/// Display success message
pub fn display_success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

/// Display error message with appropriate formatting
pub fn display_error(error: WorkflowError) {
    eprintln!("{} {}", "✗".red().bold(), error);
}

pub fn display_report(result: WorkflowResult<EncryptionReport>) {
    // display success and errors
    match result {
        Ok(report) => {
            let msg = format!(
                "Encrypted '{}' -> '{}' in {:#?}",
                report.input_filename, report.output_filename, report.duration
            );
            display_success(&msg);
        }
        Err(err) => {
            display_error(err);
        }
    }
}
