//! # PasswordRepository Interface
//!
//! Handles password input and validation (no persistence in stateless design).
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::error::Error;
use std::fmt;

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Errors that can occur during password input
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordInputError {
    /// I/O error during password reading
    IoError(String),
    /// Terminal interaction error
    TerminalError(String),
    /// Password confirmation mismatch
    MismatchError,
}

impl fmt::Display for PasswordInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordInputError::IoError(msg) => write!(f, "I/O error: {}", msg),
            PasswordInputError::TerminalError(msg) => write!(f, "Terminal error: {}", msg),
            PasswordInputError::MismatchError => write!(f, "Password confirmation mismatch"),
        }
    }
}

impl Error for PasswordInputError {}

/// Password strength assessment
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordStrength {
    Weak { issues: Vec<String> },
    Moderate,
    Strong,
}

impl PasswordStrength {
    /// Check if password strength is acceptable
    pub fn is_acceptable(&self) -> bool {
        match self {
            PasswordStrength::Weak { .. } => false,
            PasswordStrength::Moderate | PasswordStrength::Strong => true,
        }
    }
    
    /// Get human-readable description
    pub fn description(&self) -> String {
        match self {
            PasswordStrength::Weak { issues } => {
                format!("Weak password. Issues: {}", issues.join(", "))
            }
            PasswordStrength::Moderate => "Moderate password strength".to_string(),
            PasswordStrength::Strong => "Strong password".to_string(),
        }
    }
}

/// Handles password input and validation (no persistence)
pub trait PasswordRepository: Send + Sync {
    /// Prompt for password input with secure hidden input
    fn prompt_password(&self, prompt: &str) -> Result<String, PasswordInputError>;
    
    /// Prompt for password with confirmation
    fn prompt_password_with_confirmation(&self, prompt: &str) -> CryptoResult<String>;
    
    /// Validate password strength
    fn validate_password_strength(&self, password: &str) -> PasswordStrength;
}

/// Mock implementation for testing
#[derive(Debug)]
pub struct MockPasswordRepository {
    /// Predefined password responses
    password_responses: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// Control failure behavior
    should_fail: std::sync::Arc<std::sync::Mutex<bool>>,
    /// Failure error message
    failure_message: std::sync::Arc<std::sync::Mutex<String>>,
    /// Response index
    response_index: std::sync::Arc<std::sync::Mutex<usize>>,
}

impl Default for MockPasswordRepository {
    fn default() -> Self {
        Self {
            password_responses: std::sync::Arc::new(std::sync::Mutex::new(vec!["test_password".to_string()])),
            should_fail: std::sync::Arc::new(std::sync::Mutex::new(false)),
            failure_message: std::sync::Arc::new(std::sync::Mutex::new(String::new())),
            response_index: std::sync::Arc::new(std::sync::Mutex::new(0)),
        }
    }
}

impl MockPasswordRepository {
    /// Create new mock repository
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set predefined password responses
    pub fn set_password_responses(&mut self, passwords: Vec<String>) {
        if let Ok(mut responses) = self.password_responses.lock() {
            *responses = passwords;
        }
        if let Ok(mut index) = self.response_index.lock() {
            *index = 0;
        }
    }
    
    /// Configure to fail next operation
    pub fn set_should_fail(&mut self, should_fail: bool, message: impl ToString) {
        if let Ok(mut fail_flag) = self.should_fail.lock() {
            *fail_flag = should_fail;
        }
        if let Ok(mut fail_msg) = self.failure_message.lock() {
            *fail_msg = message.to_string();
        }
    }
    
    /// Reset response index
    pub fn reset_responses(&mut self) {
        if let Ok(mut index) = self.response_index.lock() {
            *index = 0;
        }
    }
}

impl PasswordRepository for MockPasswordRepository {
    fn prompt_password(&self, _prompt: &str) -> Result<String, PasswordInputError> {
        if let Ok(should_fail) = self.should_fail.lock() {
            if *should_fail {
                let msg = self.failure_message.lock()
                    .map(|m| m.clone())
                    .unwrap_or_else(|_| "Mock failure".to_string());
                return Err(PasswordInputError::IoError(msg));
            }
        }
        
        let mut index_guard = self.response_index.lock()
            .map_err(|_| PasswordInputError::IoError("Lock error".to_string()))?;
        let responses_guard = self.password_responses.lock()
            .map_err(|_| PasswordInputError::IoError("Lock error".to_string()))?;
        
        if *index_guard < responses_guard.len() {
            let password = responses_guard[*index_guard].clone();
            *index_guard += 1;
            Ok(password)
        } else {
            Err(PasswordInputError::IoError("No more password responses".to_string()))
        }
    }
    
    fn prompt_password_with_confirmation(&self, prompt: &str) -> CryptoResult<String> {
        let password1 = self.prompt_password(prompt)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        
        let confirm_prompt = &format!("Confirm {}", prompt.to_lowercase());
        let password2 = self.prompt_password(confirm_prompt)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        
        if password1 == password2 {
            Ok(password1)
        } else {
            Err(Box::new(PasswordInputError::MismatchError))
        }
    }
    
    fn validate_password_strength(&self, password: &str) -> PasswordStrength {
        // Use same validation as production implementation
        crate::infrastructure::terminal::validate_password_strength_internal(password)
    }
}