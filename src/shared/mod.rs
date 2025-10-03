//! Shared components and cryptographic primitives
//! 
//! This module provides the foundational infrastructure shared across all Shadow
//! use cases. It follows a layered architecture with clear separation between
//! core utilities, cryptographic algorithms, and version management.
//! 
//! # Architecture Overview
//! 
//! ## Core Infrastructure (`core/`)
//! - **Error handling**: Comprehensive error types and recovery mechanisms
//! - **File detection**: Encrypted file identification and validation  
//! - **Secure deletion**: Cryptographically secure file removal
//! - **Crypto utilities**: Memory protection and security monitoring
//! 
//! ## Algorithm Support (`algorithms/`)
//! - **AES-256-GCM**: High-performance authenticated encryption
//! - **XChaCha20-Poly1305**: Extended nonce authenticated encryption
//! - **Key derivation**: Argon2id with adaptive parameters
//! - **Configuration**: Flexible algorithm parameter management
//! 
//! ## Version Management (`versions/`, `versioning.rs`)
//! - **V1 format**: Original Shadow file format with AES-GCM
//! - **V2 format**: Extended format supporting multiple algorithms
//! - **Migration support**: Safe upgrades between format versions
//! - **Compatibility matrix**: Algorithm and version compatibility tracking
//! 
//! ## Utility Modules
//! - **Header management**: File header parsing and serialization
//! - **Session management**: Cryptographic session state
//! - **Progress reporting**: User feedback for long operations
//! - **Performance monitoring**: Benchmarking and optimization
//! - **CLI utilities**: Common command-line interface helpers
//! 
//! # Design Principles
//! 
//! - **Security first**: All operations prioritize cryptographic security
//! - **Version awareness**: Full support for format evolution
//! - **Performance conscious**: Optimized for real-world usage patterns
//! - **Error resilient**: Comprehensive error handling and recovery
//! - **Memory safe**: Automatic zeroization of sensitive data

// === Core Infrastructure ===
/// Error handling, file utilities, and security primitives
pub mod core;

// === Cryptographic Algorithms ===  
/// Algorithm implementations and configuration management
pub mod algorithms;

// === Version Management ===
/// Version-specific implementations and compatibility
pub mod versions;
/// Version detection and migration utilities  
pub mod versioning;
/// Cross-version dispatch and migration planning
pub mod version_dispatch;

// === File Format ===
/// Header parsing, serialization, and metadata management
pub mod header;
/// File metadata and compression type definitions
pub mod metadata;

// === User Experience ===
/// Cryptographic session state management
pub mod session;
/// Progress reporting for long-running operations
pub mod progress;
/// Performance monitoring and benchmarking
pub mod performance;
/// Common CLI utilities and helpers
pub mod cli_utils;

// === Primary API Types ===
// Core types used throughout the application
pub use core::errors::CryptoError;
pub use header::{Header, FileMetadata};
pub use algorithms::{AlgorithmId, CURRENT_VERSION, VersionInfo};
pub use metadata::CompressionType;

// === Version Management Types ===
// Types for handling different file format versions
pub use versioning::{VersionedHeader, HeaderV1, detect_version, CompatibilityMatrix};
pub use version_dispatch::{AnyHeader, VersionMigrator, MigrationPlan, MigrationStep, MigrationOperation};

// === Module Re-exports ===
// Direct access to commonly used modules
pub use core::errors;
pub use core::file_detection;
pub use core::secure_delete;
pub use core::crypto;

// === Compatibility Re-exports ===
// Version-specific functionality for backward compatibility
pub use versions::v1::filename_auth;
pub use versions::v1::header as header_core;