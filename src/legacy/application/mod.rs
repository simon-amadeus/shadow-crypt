//! # Application Services Layer
//!
//! Orchestrates domain services and manages cross-cutting concerns.

pub mod workflows;
pub mod errors;
pub mod container;

pub use errors::{ApplicationError, ApplicationResult, ErrorSeverity};
pub use container::Container;