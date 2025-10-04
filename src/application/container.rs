//! # Dependency Injection Container
//!
//! Stateless dependency injection for workflow coordination

use crate::infrastructure::{
    file_system::StandardFileRepository,
    terminal::StandardPasswordRepository,
};
use crate::application::workflows::{
    encryption_workflow::EncryptionWorkflow,
    decryption_workflow::DecryptionWorkflow,
    listing_workflow::ListingWorkflow,
    migration_workflow::MigrationWorkflow,
};
use crate::domain::entities::AlgorithmId;

/// Dependency injection container for stateless workflow coordination
pub struct Container;

impl Container {
    /// Create container with standard implementations
    pub fn new() -> Self {
        Self
    }
    
    /// Create EncryptionWorkflow instance
    pub fn encryption_workflow(&self, algorithm: AlgorithmId) -> EncryptionWorkflow {
        EncryptionWorkflow::new(
            Box::new(StandardFileRepository::new()),
            Box::new(StandardPasswordRepository::new()),
            algorithm,
        )
    }
    
    /// Create DecryptionWorkflow instance
    pub fn decryption_workflow(&self) -> DecryptionWorkflow {
        DecryptionWorkflow::new(
            Box::new(StandardFileRepository::new()),
            Box::new(StandardPasswordRepository::new()),
        )
    }
    
    /// Create ListingWorkflow instance
    pub fn listing_workflow(&self) -> ListingWorkflow {
        ListingWorkflow::new(
            Box::new(StandardFileRepository::new()),
            Box::new(StandardPasswordRepository::new()),
        )
    }
    
    /// Create MigrationWorkflow instance
    pub fn migration_workflow(&self) -> MigrationWorkflow {
        MigrationWorkflow::new(
            Box::new(StandardFileRepository::new()),
            Box::new(StandardPasswordRepository::new()),
        )
    }
}