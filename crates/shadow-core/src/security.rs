// shadow-core/src/security.rs
// Algorithm-agnostic security profile definitions

/// Security profiles defining cryptographic strength levels
///
/// This is algorithm-agnostic - different algorithms interpret these profiles
/// according to their own parameter systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Fast parameters for development/testing only
    ///
    /// **WARNING: This provides minimal security and should NEVER be used in production**
    Test,

    /// Production-grade security parameters
    ///
    /// Provides strong security suitable for protecting real data.
    Production,
}

impl SecurityProfile {
    /// Get a human-readable description of this security profile
    pub fn description(&self) -> &'static str {
        match self {
            SecurityProfile::Test => "Fast (Test-only)",
            SecurityProfile::Production => "Secure (Production)",
        }
    }

    /// Check if this profile is suitable for production use
    pub fn is_production_safe(&self) -> bool {
        matches!(self, SecurityProfile::Production)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_profile_descriptions() {
        assert_eq!(SecurityProfile::Test.description(), "Fast (Test-only)");
        assert_eq!(SecurityProfile::Production.description(), "Secure (Production)");
    }

    #[test]
    fn test_production_safety_check() {
        assert!(!SecurityProfile::Test.is_production_safe());
        assert!(SecurityProfile::Production.is_production_safe());
    }
}