//! Algorithm capability registry for Shadow encryption
//! 
//! This module provides a registry of available cryptographic algorithms
//! and their capabilities for runtime algorithm selection.

use crate::shared::algorithms::selection::Algorithm;

/// Algorithm capability information
#[derive(Debug, Clone)]
pub struct AlgorithmCapability {
    pub algorithm: Algorithm,
    pub name: &'static str,
    pub description: &'static str,
    pub key_size: usize,
    pub nonce_size: usize,
    pub auth_tag_size: usize,
    pub post_quantum: bool,
    pub hardware_accelerated: bool,
}

/// Get all available algorithm capabilities
pub fn get_available_algorithms() -> Vec<AlgorithmCapability> {
    vec![
        AlgorithmCapability {
            algorithm: Algorithm::AES256GCM,
            name: "AES-256-GCM",
            description: "AES-256 in Galois/Counter Mode with Argon2 key derivation",
            key_size: 32,
            nonce_size: 12,
            auth_tag_size: 16,
            post_quantum: false,
            hardware_accelerated: true, // Most modern processors support AES-NI
        },
        // Future algorithms will be added here
    ]
}

/// Get capability information for a specific algorithm
pub fn get_algorithm_capability(algorithm: Algorithm) -> Option<AlgorithmCapability> {
    get_available_algorithms()
        .into_iter()
        .find(|cap| cap.algorithm == algorithm)
}

/// Check if an algorithm is available on this system
pub fn is_algorithm_available(algorithm: Algorithm) -> bool {
    get_algorithm_capability(algorithm).is_some()
}

/// Get the best available algorithm based on requirements
pub fn select_best_algorithm(prefer_post_quantum: bool, require_hardware_accel: bool) -> Option<Algorithm> {
    let algorithms = get_available_algorithms();
    
    // Filter based on requirements
    let suitable: Vec<_> = algorithms.iter()
        .filter(|cap| {
            if prefer_post_quantum && !cap.post_quantum {
                return false;
            }
            if require_hardware_accel && !cap.hardware_accelerated {
                return false;
            }
            true
        })
        .collect();
    
    // Return the first suitable algorithm (they're ordered by preference)
    suitable.first().map(|cap| cap.algorithm)
}