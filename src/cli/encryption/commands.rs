//! Command parsing for the functional pipeline.

use crate::core::{AlgorithmId, EncryptionOptions};

/// Encryption command arguments.
#[derive(Debug, Clone)]
pub struct EncryptCommand {
    pub input_patterns: Vec<String>,
    pub algorithm: AlgorithmId,
    pub obfuscate: bool,
    pub force: bool,
    pub keep: bool,
    pub quiet: bool,
}

impl Default for EncryptCommand {
    fn default() -> Self {
        Self {
            input_patterns: Vec::new(),
            algorithm: AlgorithmId::recommended(),
            obfuscate: false,
            force: false,
            keep: false,
            quiet: false,
        }
    }
}

impl EncryptCommand {
    /// Convert to encryption options.
    pub fn to_options(&self) -> EncryptionOptions {
        EncryptionOptions {
            algorithm: self.algorithm,
            obfuscate_filename: self.obfuscate,
            force_overwrite: self.force,
            remove_source: !self.keep, // keep=true means remove_source=false
            check_duplicates: true,
        }
    }
}

/// Parse command line arguments (simplified version).
pub fn parse_encrypt_args(args: Vec<String>) -> Result<EncryptCommand, String> {
    let mut command = EncryptCommand::default();
    
    if args.len() < 2 {
        return Err("Usage: shadow <file_patterns...>".to_string());
    }
    
    // Skip the program name
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--obfuscate" | "-o" => {
                command.obfuscate = true;
            }
            "--force" | "-f" => {
                command.force = true;
            }
            "--keep" | "-k" => {
                command.keep = true;
            }
            "--quiet" | "-q" => {
                command.quiet = true;
            }
            "--algorithm" | "-a" => {
                i += 1;
                if i >= args.len() {
                    return Err("--algorithm requires a value".to_string());
                }
                match args[i].as_str() {
                    "aes" | "aes256" => command.algorithm = AlgorithmId::AesGcm256,
                    "xchacha20" | "xchacha" => command.algorithm = AlgorithmId::XChaCha20Poly1305,
                    _ => return Err(format!("Unknown algorithm: {}", args[i])),
                }
            }
            arg if arg.starts_with('-') => {
                return Err(format!("Unknown option: {}", arg));
            }
            _ => {
                // Input pattern
                command.input_patterns.push(args[i].clone());
            }
        }
        i += 1;
    }
    
    if command.input_patterns.is_empty() {
        return Err("No input files specified".to_string());
    }
    
    Ok(command)
}