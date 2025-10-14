//! # File Operations Domain Slice
//!
//! Business capability: Type-safe file I/O with atomic transactions.

pub mod handler;

// Re-export public interface
pub use handler::{
    FileHandler,
    FileTransaction,
    TransactionBuilder,
    FileOperation,
    FileResult,
};