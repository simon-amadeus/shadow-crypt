//! # DecryptionService
//!
//! Orchestrates file decryption with filename restoration.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use crate::domain::entities::{AlgorithmId, header::TlvFieldType};
use crate::domain::errors::{DomainResult, DomainError, FileSystemError};
use crate::domain::services::{FileDetector, CryptographicAlgorithm};
use crate::domain::services::crypto_service::KeyDerivationConfig;
use crate::domain::services::encryption_service::BatchResult;


#[derive(Debug, Clone)]
pub struct DecryptionOptions {
    pub force_overwrite: bool,
    pub remove_source: bool,
    pub verify_integrity: bool,
}

#[derive(Debug)]
pub struct DecryptionResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub original_filename: Option<String>,
    pub algorithm: AlgorithmId,
    pub duration: Duration,
}
