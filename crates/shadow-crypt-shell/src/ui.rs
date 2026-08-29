use colored::Colorize;
use shadow_crypt_core::{
    profile::SecurityProfile,
    progress::ProgressCounter,
    report::{DecryptionReport, EncryptionReport, KeyDerivationReport},
    v3::key::KeyDerivationParams,
};

use crate::{errors::WorkflowError, listing::file::FileInfoList};

pub fn display_progress(counter: &ProgressCounter) {
    println!(
        "Processed file {} of {}",
        counter.get_current(),
        counter.get_total()
    );
}

pub fn display_success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

pub fn display_error(error: &WorkflowError) {
    eprintln!("{} {}", "✗".red().bold(), error);
}

pub fn display_warning(message: &str) {
    eprintln!("{} {}", "!".yellow().bold(), message);
}

/// Prints every security profile with its Argon2id parameters (as written by
/// the current format version), so the costs are inspectable without reading
/// code.
pub fn display_profiles() {
    println!("{}", "Security Profiles (Argon2id key derivation)".bold());
    println!();

    let profiles = [
        (
            SecurityProfile::Standard,
            "standard",
            "(default)",
            "OWASP Password Storage Cheat Sheet recommended configuration,\n\
             using the highest-memory option of the equivalent set.",
        ),
        (
            SecurityProfile::Paranoid,
            "paranoid",
            "",
            "Maximum-cost derivation for high-value archives.\n\
             Needs 1 GiB of free RAM and takes seconds per file.",
        ),
        (
            SecurityProfile::Test,
            "test",
            "",
            "For automated testing only — insecure, and password strength\n\
             checks are skipped.",
        ),
    ];

    for (profile, name, tag, description) in profiles {
        let params = KeyDerivationParams::from(profile);
        println!("  {} {}", name.bold().cyan(), tag.dimmed());
        println!(
            "      memory {} MiB, iterations {}, parallelism {}, key size {} bytes",
            params.memory_cost / 1024,
            params.time_cost,
            params.parallelism,
            params.key_size
        );
        for line in description.lines() {
            println!("      {}", line.trim().dimmed());
        }
        println!();
    }

    println!("Files record their parameters in the header, so any profile decrypts");
    println!("with any build of this tool.");
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

pub fn display_encryption_success(report: &EncryptionReport) {
    let msg = format!(
        "Encrypted '{}' -> '{}' in {:#?} using {}",
        report.input_filename, report.output_filename, report.duration, report.algorithm
    );
    display_success(&msg);
    if report.original_deleted {
        println!("  Deleted original '{}'.", report.input_filename);
    } else {
        println!(
            "  Note: '{}' was not deleted — remove it manually if it is no longer needed.",
            report.input_filename
        );
    }
}

pub fn display_decryption_success(report: &DecryptionReport) {
    let msg = format!(
        "Decrypted '{}' -> '{}' in {:#?} using {}",
        report.input_filename, report.output_filename, report.duration, report.algorithm
    );
    display_success(&msg);
}

/// Displays the listing. `names_requested` says whether original filenames
/// were decrypted (a password was provided); without it only the plaintext
/// header metadata is shown.
pub fn display_file_info_list(info_list: &FileInfoList, names_requested: bool) {
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
    if names_requested {
        println!(
            "{:<30} {:<30} {:<10} {:<10}",
            "Original Filename".bold(),
            "Obfuscated Filename".bold(),
            "Version".bold(),
            "Size".bold()
        );
    } else {
        println!(
            "{:<30} {:<10} {:<10}",
            "Obfuscated Filename".bold(),
            "Version".bold(),
            "Size".bold()
        );
    }
    println!("{}", "─".repeat(80).dimmed());

    // Print each file info
    for info in &sorted_items {
        let obfuscated = &info.obfuscated_filename;
        let version = info.version.as_str().cyan();
        let size = format_size(info.size).blue();

        if names_requested {
            let original = match &info.original_filename {
                Some(name) => name.as_str().green(),
                None => "N/A".red(),
            };
            println!(
                "{:<30} {:<30} {:<10} {:<10}",
                truncate_string(&original, 28),
                truncate_string(obfuscated, 28),
                version,
                size
            );
        } else {
            println!(
                "{:<30} {:<10} {:<10}",
                truncate_string(obfuscated, 28),
                version,
                size
            );
        }
    }

    println!();
    println!("{} files found", info_list.items.len().to_string().bold());

    if names_requested {
        let decrypted = sorted_items
            .iter()
            .filter(|i| i.original_filename.is_some())
            .count();
        if decrypted == 0 {
            println!(
                "{}",
                "No filenames could be decrypted — wrong password?".yellow()
            );
        }
    } else {
        println!(
            "{}",
            "Run with --names to decrypt the original filenames.".dimmed()
        );
    }
}

/// Prints the listing as a JSON array on stdout, for scripting.
/// `original_filename` is null when names were not requested or a name
/// could not be decrypted.
pub fn display_file_info_list_json(info_list: &FileInfoList) {
    println!("[");
    for (i, info) in info_list.items.iter().enumerate() {
        let original = match &info.original_filename {
            Some(name) => format!("\"{}\"", json_escape(name.as_str())),
            None => "null".to_string(),
        };
        let comma = if i + 1 < info_list.items.len() {
            ","
        } else {
            ""
        };
        println!(
            "  {{\"obfuscated_filename\":\"{}\",\"version\":\"{}\",\"size\":{},\"original_filename\":{}}}{}",
            json_escape(&info.obfuscated_filename),
            info.version.as_str(),
            info.size,
            original,
            comma
        );
    }
    println!("]");
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("plain.txt"), "plain.txt");
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("line\nbreak\ttab"), "line\\nbreak\\ttab");
        assert_eq!(json_escape("bell\u{07}"), "bell\\u0007");
        assert_eq!(json_escape("unicode café 日本"), "unicode café 日本");
    }
}
