//! Core cryptographic utilities
//! 
//! This module contains cryptographic utilities that are truly shared
//! across all algorithms and versions - security monitoring, memory protection, etc.

pub mod secure_memory;
pub mod nonce_tracking;
pub mod timing_analysis;

// Re-export commonly used types and functions
pub use secure_memory::{SecretVec, KeyMaterial};
pub use nonce_tracking::{check_nonce_reuse, validate_nonce_entropy, get_nonce_statistics};
pub use timing_analysis::{TimingAnalyzer, TimingAnalysisResult, run_timing_security_tests};