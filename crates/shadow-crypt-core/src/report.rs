use std::time::Duration;

use crate::algorithm::Algorithm;

pub struct EncryptionReport {
    pub input_filename: String,
    pub output_filename: String,
    pub duration: Duration,
    pub algorithm: Algorithm,
    /// Whether the original was deleted after successful encryption.
    pub original_deleted: bool,
}
impl EncryptionReport {
    pub fn new(
        input_filename: String,
        output_filename: String,
        duration: Duration,
        algorithm: Algorithm,
        original_deleted: bool,
    ) -> Self {
        Self {
            input_filename,
            output_filename,
            duration,
            algorithm,
            original_deleted,
        }
    }
}

pub struct DecryptionReport {
    pub input_filename: String,
    pub output_filename: String,
    pub duration: Duration,
    pub algorithm: Algorithm,
}
impl DecryptionReport {
    pub fn new(
        input_filename: String,
        output_filename: String,
        duration: Duration,
        algorithm: Algorithm,
    ) -> Self {
        Self {
            input_filename,
            output_filename,
            duration,
            algorithm,
        }
    }
}

#[derive(Debug)]
pub struct KeyDerivationReport {
    pub algorithm: String,
    pub algorithm_version: String,
    pub memory_cost_kib: u32,
    pub time_cost_iterations: u32,
    pub parallelism: u32,
    pub key_size_bytes: u8,
    pub duration: std::time::Duration,
}
impl KeyDerivationReport {
    /// Takes raw parameter values so the report stays independent of any
    /// version-specific `KeyDerivationParams` type.
    pub fn new(
        algorithm: String,
        algorithm_version: String,
        memory_cost_kib: u32,
        time_cost_iterations: u32,
        parallelism: u32,
        key_size_bytes: u8,
        duration: std::time::Duration,
    ) -> Self {
        Self {
            algorithm,
            algorithm_version,
            memory_cost_kib,
            time_cost_iterations,
            parallelism,
            key_size_bytes,
            duration,
        }
    }
}
