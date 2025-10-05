//! Shadow Infrastructure - External adapters implementing domain abstractions
//! This crate provides concrete implementations of domain interfaces.

pub mod crypto;
pub mod file_system;
pub mod terminal;
pub mod progress;
pub mod tlv_serialization;
pub mod errors;