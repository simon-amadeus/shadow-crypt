// shadow-core/src/lib.rs
// Core cryptographic functionality for the Shadow file encryption format

mod algorithms; // Cryptographic algorithm implementations
pub mod encryption;
pub mod memory;
pub mod v1;

// Re-export main types and utilities
pub use algorithms::xchacha20_poly1305;
