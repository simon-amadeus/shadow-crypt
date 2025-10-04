//! # Application Services Layer
//!
//! Orchestrates domain services and manages cross-cutting concerns.

pub mod workflows;
pub mod errors;

pub use errors::{ApplicationError, ApplicationResult, ErrorSeverity};