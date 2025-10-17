// shadow-core/src/algorithms/mod.rs
// Top-level cryptographic algorithms - vertically sliced by algorithm

pub mod argon2;
pub mod xchacha20_poly1305;

// Re-export for convenience - but each algorithm slice is self-contained
pub use argon2::{SecurityProfile};
pub use xchacha20_poly1305::{ALGORITHM_ID as XCHACHA20_POLY1305_ID};