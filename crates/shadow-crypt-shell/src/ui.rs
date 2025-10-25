use colored::Colorize;
use shadow_crypt_core::{
    progress::ProgressCounter,
    report::{DecryptionReport, EncryptionReport, KeyDerivationReport},
};

use crate::{
    errors::{WorkflowError, WorkflowResult},
    listing::file::FileInfoList,
};

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

pub fn display_file_info_list(info_list: &FileInfoList) {
    if info_list.items.is_empty() {
        println!("{}", "No shadow files found.".yellow());
        return;
    }

    // Sort the items: files with original names first (alphabetically), then files without
    let mut sorted_items = info_list.items.clone();
    sorted_items.sort_by(|a, b| match (&a.original_filename, &b.original_filename) {
        (Some(name_a), Some(name_b)) => name_a.as_str().cmp(name_b.as_str()),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.obfuscated_filename.cmp(&b.obfuscated_filename),
    });

    // Print header
    println!("{}", "Shadow Files Listing".bold().underline());
    println!();

    // Column headers
    println!(
        "{:<30} {:<30} {:<10} {:<10}",
        "Original Filename".bold(),
        "Obfuscated Filename".bold(),
        "Version".bold(),
        "Size".bold()
    );
    println!("{}", "─".repeat(80).dimmed());

    // Print each file info
    for info in &sorted_items {
        let original = match &info.original_filename {
            Some(name) => name.as_str().green(),
            None => "N/A".red(),
        };

        let obfuscated = &info.obfuscated_filename;
        let version = info.version.as_str().cyan();
        let size = format_size(info.size).blue();

        println!(
            "{:<30} {:<30} {:<10} {:<10}",
            truncate_string(&original, 28),
            truncate_string(obfuscated, 28),
            version,
            size
        );
    }

    println!();
    println!("{} files found", info_list.items.len().to_string().bold());
}

fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
