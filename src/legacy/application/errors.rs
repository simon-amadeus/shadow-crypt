//! # Application Error Types
//! 
//! Application layer error handling for workflow orchestration
//! and service coordination.

use crate::domain::errors::DomainError;
use crate::infrastructure::errors::InfrastructureError;
use std::fmt;

/// Application layer specific errors
#[derive(Debug)]
pub enum ApplicationError {
    /// Domain operation failed
    Domain(DomainError),
    
    /// Infrastructure operation failed
    Infrastructure(InfrastructureError),
    
    /// Workflow orchestration failed
    Workflow(WorkflowError),
    
    /// Service coordination failed
    ServiceCoordination(ServiceCoordinationError),
    
    /// Validation pipeline failed
    Validation(ValidationError),
}

/// Workflow orchestration errors
#[derive(Debug, Clone)]
pub enum WorkflowError {
    /// Workflow step failed
    StepFailed { step: String, reason: String },
    
    /// Workflow aborted due to user action
    WorkflowAborted { workflow: String, reason: String },
    
    /// Workflow prerequisites not met
    PrerequisitesNotMet { workflow: String, missing: Vec<String> },
    
    /// Workflow state inconsistent
    InconsistentState { workflow: String, state: String },
    
    /// Batch operation partially failed
    PartialFailure { total: usize, failed: usize, error_count: usize },
}

/// Service coordination errors
#[derive(Debug, Clone)]
pub enum ServiceCoordinationError {
    /// Service unavailable
    ServiceUnavailable { service: String },
    
    /// Service configuration invalid
    InvalidServiceConfiguration { service: String, reason: String },
    
    /// Service dependency failure
    DependencyFailure { service: String, dependency: String, reason: String },
    
    /// Service timeout
    ServiceTimeout { service: String, timeout_seconds: u64 },
    
    /// Service communication failed
    CommunicationFailed { service: String, reason: String },
}

/// Validation pipeline errors
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// Input validation failed
    InputValidationFailed { field: String, reason: String },
    
    /// Business rule validation failed
    BusinessRuleViolation { rule: String, reason: String },
    
    /// Security validation failed
    SecurityValidationFailed { check: String, reason: String },
    
    /// Consistency validation failed
    ConsistencyValidationFailed { context: String, reason: String },
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplicationError::Domain(err) => write!(f, "Domain error: {}", err),
            ApplicationError::Infrastructure(err) => write!(f, "Infrastructure error: {}", err),
            ApplicationError::Workflow(err) => write!(f, "Workflow error: {}", err),
            ApplicationError::ServiceCoordination(err) => write!(f, "Service coordination error: {}", err),
            ApplicationError::Validation(err) => write!(f, "Validation error: {}", err),
        }
    }
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkflowError::StepFailed { step, reason } => 
                write!(f, "Workflow step '{}' failed: {}", step, reason),
            WorkflowError::WorkflowAborted { workflow, reason } => 
                write!(f, "Workflow '{}' aborted: {}", workflow, reason),
            WorkflowError::PrerequisitesNotMet { workflow, missing } => 
                write!(f, "Workflow '{}' prerequisites not met: {}", workflow, missing.join(", ")),
            WorkflowError::InconsistentState { workflow, state } => 
                write!(f, "Workflow '{}' has inconsistent state: {}", workflow, state),
            WorkflowError::PartialFailure { total, failed, .. } => 
                write!(f, "Batch operation partial failure: {}/{} operations failed", failed, total),
        }
    }
}

impl fmt::Display for ServiceCoordinationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceCoordinationError::ServiceUnavailable { service } => 
                write!(f, "Service '{}' unavailable", service),
            ServiceCoordinationError::InvalidServiceConfiguration { service, reason } => 
                write!(f, "Service '{}' configuration invalid: {}", service, reason),
            ServiceCoordinationError::DependencyFailure { service, dependency, reason } => 
                write!(f, "Service '{}' dependency '{}' failed: {}", service, dependency, reason),
            ServiceCoordinationError::ServiceTimeout { service, timeout_seconds } => 
                write!(f, "Service '{}' timeout after {} seconds", service, timeout_seconds),
            ServiceCoordinationError::CommunicationFailed { service, reason } => 
                write!(f, "Service '{}' communication failed: {}", service, reason),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::InputValidationFailed { field, reason } => 
                write!(f, "Input validation failed for '{}': {}", field, reason),
            ValidationError::BusinessRuleViolation { rule, reason } => 
                write!(f, "Business rule '{}' violated: {}", rule, reason),
            ValidationError::SecurityValidationFailed { check, reason } => 
                write!(f, "Security validation '{}' failed: {}", check, reason),
            ValidationError::ConsistencyValidationFailed { context, reason } => 
                write!(f, "Consistency validation failed in '{}': {}", context, reason),
        }
    }
}

impl std::error::Error for ApplicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ApplicationError::Domain(err) => Some(err),
            ApplicationError::Infrastructure(err) => Some(err),
            _ => None,
        }
    }
}

// Conversion implementations for error propagation
impl From<DomainError> for ApplicationError {
    fn from(error: DomainError) -> Self {
        ApplicationError::Domain(error)
    }
}

impl From<InfrastructureError> for ApplicationError {
    fn from(error: InfrastructureError) -> Self {
        ApplicationError::Infrastructure(error)
    }
}

impl From<WorkflowError> for ApplicationError {
    fn from(error: WorkflowError) -> Self {
        ApplicationError::Workflow(error)
    }
}

impl From<ServiceCoordinationError> for ApplicationError {
    fn from(error: ServiceCoordinationError) -> Self {
        ApplicationError::ServiceCoordination(error)
    }
}

impl From<ValidationError> for ApplicationError {
    fn from(error: ValidationError) -> Self {
        ApplicationError::Validation(error)
    }
}

impl ApplicationError {
    /// Get user-friendly error message with actionable suggestions
    pub fn user_friendly_message(&self) -> String {
        match self {
            ApplicationError::Domain(err) => err.user_friendly_message(),
            ApplicationError::Infrastructure(err) => err.user_friendly_message(),
            ApplicationError::Workflow(err) => err.user_friendly_message(),
            ApplicationError::ServiceCoordination(err) => err.user_friendly_message(),
            ApplicationError::Validation(err) => err.user_friendly_message(),
        }
    }

    /// Check if this error suggests a wrong password
    pub fn suggests_wrong_password(&self) -> bool {
        match self {
            ApplicationError::Domain(err) => err.suggests_wrong_password(),
            _ => false,
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            ApplicationError::Domain(err) => err.is_recoverable(),
            ApplicationError::Workflow(WorkflowError::PartialFailure { .. }) => true,
            ApplicationError::Validation(_) => true,
            _ => false,
        }
    }

    /// Check if this error indicates potential security issue
    pub fn is_security_related(&self) -> bool {
        match self {
            ApplicationError::Domain(err) => err.is_security_related(),
            ApplicationError::Validation(ValidationError::SecurityValidationFailed { .. }) => true,
            _ => false,
        }
    }

    /// Get error severity level
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            ApplicationError::Domain(err) => {
                if err.is_security_related() {
                    ErrorSeverity::Critical
                } else if err.suggests_wrong_password() {
                    ErrorSeverity::Warning
                } else {
                    ErrorSeverity::Error
                }
            }
            ApplicationError::Workflow(WorkflowError::PartialFailure { .. }) => ErrorSeverity::Warning,
            ApplicationError::Validation(ValidationError::SecurityValidationFailed { .. }) => ErrorSeverity::Critical,
            ApplicationError::Validation(_) => ErrorSeverity::Warning,
            _ => ErrorSeverity::Error,
        }
    }
}

/// Error severity levels for user interface presentation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Warning - operation can be retried or ignored
    Warning,
    /// Error - operation failed but system is stable
    Error,
    /// Critical - security issue or system integrity compromised
    Critical,
}

impl WorkflowError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            WorkflowError::StepFailed { step, .. } => {
                format!("Operation '{}' failed.\n\n\
                Suggestions:\n\
                • Review the error details above for specific guidance\n\
                • Check that all input files are accessible\n\
                • Verify you have necessary permissions", step)
            }
            WorkflowError::PrerequisitesNotMet { workflow, missing } => {
                format!("Cannot start '{}' - missing requirements: {}\n\n\
                Suggestions:\n\
                • Ensure all required files and inputs are available\n\
                • Check configuration settings\n\
                • Review the help documentation for requirements", workflow, missing.join(", "))
            }
            WorkflowError::PartialFailure { total, failed, .. } => {
                format!("Batch operation completed with {} failures out of {} total operations.\n\n\
                Suggestions:\n\
                • Review individual error messages above\n\
                • Retry failed operations individually\n\
                • Check file permissions and disk space", failed, total)
            }
            _ => format!("Workflow error: {}\n\nThe operation could not be completed", self),
        }
    }
}

impl ServiceCoordinationError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            ServiceCoordinationError::ServiceUnavailable { service } => {
                format!("Service '{}' is not available.\n\n\
                Suggestions:\n\
                • Check system requirements and dependencies\n\
                • Verify service configuration\n\
                • Restart the application if needed", service)
            }
            ServiceCoordinationError::ServiceTimeout { service, timeout_seconds } => {
                format!("Service '{}' timed out after {} seconds.\n\n\
                Suggestions:\n\
                • The operation may be taking longer than expected\n\
                • Check system performance and available resources\n\
                • Try with smaller input if processing large files", service, timeout_seconds)
            }
            _ => format!("Service coordination error: {}\n\nA system service is not functioning properly", self),
        }
    }
}

impl ValidationError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            ValidationError::InputValidationFailed { field, reason } => {
                format!("Invalid input for '{}': {}\n\n\
                Suggestions:\n\
                • Check the input format and requirements\n\
                • Review the help documentation for examples\n\
                • Use --help flag for parameter guidance", field, reason)
            }
            ValidationError::BusinessRuleViolation { rule, reason } => {
                format!("Operation violates business rule '{}': {}\n\n\
                Suggestions:\n\
                • Review the operation requirements\n\
                • Check if the operation is appropriate for this context\n\
                • Contact support if you believe this is an error", rule, reason)
            }
            ValidationError::SecurityValidationFailed { check, .. } => {
                format!("Security validation '{}' failed.\n\n\
                This operation was blocked for security reasons.\n\
                Please review the operation and try again with valid inputs.", check)
            }
            _ => format!("Validation error: {}\n\nPlease check your inputs and try again", self),
        }
    }
}

/// Convenience result type for application operations
pub type ApplicationResult<T> = Result<T, ApplicationError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::errors::*;

    #[test]
    fn test_domain_error_conversion() {
        let domain_err = DomainError::AuthenticationFailed {
            context: "test".to_string(),
        };
        let app_err: ApplicationError = domain_err.into();
        
        match app_err {
            ApplicationError::Domain(DomainError::AuthenticationFailed { .. }) => {},
            _ => panic!("Expected Domain error with AuthenticationFailed"),
        }
    }

    #[test]
    fn test_workflow_error_user_friendly_message() {
        let error = WorkflowError::PartialFailure {
            total: 10,
            failed: 3,
            error_count: 3,
        };
        let message = error.user_friendly_message();
        assert!(message.contains("3 failures out of 10"));
        assert!(message.contains("Review individual error messages"));
    }

    #[test]
    fn test_error_severity() {
        let security_err = ApplicationError::Validation(ValidationError::SecurityValidationFailed {
            check: "test".to_string(),
            reason: "test".to_string(),
        });
        assert_eq!(security_err.severity(), ErrorSeverity::Critical);

        let warning_err = ApplicationError::Workflow(WorkflowError::PartialFailure {
            total: 5,
            failed: 1,
            error_count: 1,
        });
        assert_eq!(warning_err.severity(), ErrorSeverity::Warning);
    }

    #[test]
    fn test_suggests_wrong_password_propagation() {
        let domain_err = DomainError::AuthenticationFailed {
            context: "test".to_string(),
        };
        let app_err = ApplicationError::Domain(domain_err);
        assert!(app_err.suggests_wrong_password());
    }

    #[test]
    fn test_is_recoverable() {
        let validation_err = ApplicationError::Validation(ValidationError::InputValidationFailed {
            field: "test".to_string(),
            reason: "test".to_string(),
        });
        assert!(validation_err.is_recoverable());
    }
}