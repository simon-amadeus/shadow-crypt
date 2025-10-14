//! # EncryptionService
//!
//! Orchestrates file encryption with all features.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use crate::domain::entities::encrypted_file::EncryptedFile;
use crate::domain::entities::plaintext_file::{self, ContentHash, PlaintextFile};
use crate::domain::entities::{header::{TlvHeader, TlvFieldType}, AlgorithmId};
use crate::domain::errors::{DomainError, DomainResult, FileSystemError};
use crate::domain::services::{FileDetector, CryptographicAlgorithm};


pub trait EncryptionService {
    fn encrypt(plaintext_file: &PlaintextFile) -> Result<EncryptedFile, DomainError>;
}