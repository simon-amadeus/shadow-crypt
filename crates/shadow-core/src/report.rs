use std::time::Duration;

use crate::{algorithm::Algorithm, v1::key::KeyDerivationParams};

pub struct EncryptionReport {
    pub input_filename: String,
    pub output_filename: String,
    pub duration: Duration,
    pub algorithm: Algorithm,
}
impl EncryptionReport {
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
    pub fn new(
        algorithm: String,
        algorithm_version: String,
        params: &KeyDerivationParams,
        duration: std::time::Duration,
    ) -> Self {
        Self {
            algorithm,
            algorithm_version,
            memory_cost_kib: params.memory_cost,
            time_cost_iterations: params.time_cost,
            parallelism: params.parallelism,
            key_size_bytes: params.key_size,
            duration,
        }
    }
}
