use colored::Colorize;
use shadow_core::{
    progress::ProgressCounter,
    report::{DecryptionReport, EncryptionReport, KeyDerivationReport},
};

use crate::errors::{WorkflowError, WorkflowResult};

pub fn display_progress(counter: &ProgressCounter) {
    println!(
        "Processing file {} of {}",
        counter.get_current(),
        counter.get_total()
    );
}

pub fn display_success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

pub fn display_error(error: WorkflowError) {
    eprintln!("{} {}", "✗".red().bold(), error);
}

pub fn display_key_derivation_report(report: &KeyDerivationReport) {
    println!("Derived key in {:#?}:", report.duration);
    println!("  Algorithm: {}", report.algorithm);
    println!("  Version: {}", report.algorithm_version);
    println!(
        "  Memory Cost (KiB): {} ({} MiB)",
        report.memory_cost_kib,
        report.memory_cost_kib / 1024
    );
    println!("  Time Cost (Iterations): {}", report.time_cost_iterations);
    println!("  Parallelism: {}", report.parallelism);
    println!("  Key Size (Bytes): {}", report.key_size_bytes);
}

pub fn display_encryption_report(result: WorkflowResult<EncryptionReport>) {
    match result {
        Ok(report) => {
            let msg = format!(
                "Encrypted '{}' -> '{}' in {:#?} using {}",
                report.input_filename, report.output_filename, report.duration, report.algorithm
            );
            display_success(&msg);
        }
        Err(err) => {
            display_error(err);
        }
    }
}

pub fn display_decryption_report(result: WorkflowResult<DecryptionReport>) {
    match result {
        Ok(report) => {
            let msg = format!(
                "Decrypted '{}' -> '{}' in {:#?} using {}",
                report.input_filename, report.output_filename, report.duration, report.algorithm
            );
            display_success(&msg);
        }
        Err(err) => {
            display_error(err);
        }
    }
}
