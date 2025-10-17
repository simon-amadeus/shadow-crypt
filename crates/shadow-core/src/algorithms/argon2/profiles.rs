// shadow-core/src/crypto/algorithms/argon2/profiles.rs
// Argon2 security profiles and parameter configurations

use argon2::{Algorithm, Argon2, Params, Version};

/// Security profiles defining cryptographic parameter sets for Argon2
///
/// Provides two distinct configurations aligned with KISS and YAGNI principles:
/// - Test: Fast parameters for development and testing
/// - Production: Strong parameters for real-world security
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Fast parameters for development/testing only
    ///
    /// **WARNING: These parameters provide minimal security and should NEVER be used in production**
    ///
    /// Parameters:
    /// - Memory Cost: 64 KiB
    /// - Time Cost: 1 iteration  
    /// - Parallelism: 1 thread
    Test,

    /// Production-grade security parameters
    ///
    /// These parameters provide strong security suitable for protecting real data.
    /// Based on current cryptographic recommendations as of 2025.
    ///
    /// Parameters:
    /// - Memory Cost: 1 GiB (1,048,576 KiB)
    /// - Time Cost: 5 iterations
    /// - Parallelism: 4 threads
    Production,
}

impl SecurityProfile {
    /// Get Argon2 parameters for this security profile
    ///
    /// Returns properly configured Argon2 parameters that match the
    /// security requirements for each profile.
    ///
    /// # Panics
    ///
    /// Panics if the hardcoded parameters are invalid (should never happen
    /// in practice as these are well-tested parameter combinations).
    pub fn argon2_params(&self) -> Params {
        match self {
            SecurityProfile::Test => {
                // Fast parameters - suitable for testing only
                Params::new(
                    64,   // m_cost: 64 KiB memory
                    1,    // t_cost: 1 iteration
                    1,    // p_cost: 1 thread
                    None, // output_len: use default (32 bytes)
                )
                .expect("Test Argon2 parameters should be valid")
            }
            SecurityProfile::Production => {
                // Strong parameters - suitable for production
                Params::new(
                    1_048_576, // m_cost: 1 GiB memory
                    5,         // t_cost: 5 iterations
                    4,         // p_cost: 4 threads
                    None,      // output_len: use default (32 bytes)
                )
                .expect("Production Argon2 parameters should be valid")
            }
        }
    }

    /// Create a configured Argon2 instance for this security profile
    ///
    /// Returns an Argon2 instance using Argon2id algorithm with parameters
    /// appropriate for this security profile.
    pub fn create_argon2(&self) -> Argon2<'static> {
        let params = self.argon2_params();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }

    /// Get a human-readable description of this security profile
    ///
    /// Useful for logging and user feedback about which security
    /// profile is being used.
    pub fn description(&self) -> &'static str {
        match self {
            SecurityProfile::Test => "Fast (Test-only)",
            SecurityProfile::Production => "Secure (Production)",
        }
    }

    /// Check if this profile is suitable for production use
    ///
    /// Returns `false` for Test profile to help prevent accidental
    /// use in production environments.
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

    #[test]
    fn test_argon2_instance_creation() {
        let _test_argon2 = SecurityProfile::Test.create_argon2();
        let _prod_argon2 = SecurityProfile::Production.create_argon2();

        // Verify they're different instances with different parameters
        let test_params = SecurityProfile::Test.argon2_params();
        let prod_params = SecurityProfile::Production.argon2_params();

        assert_ne!(test_params.m_cost(), prod_params.m_cost());
        assert_ne!(test_params.t_cost(), prod_params.t_cost());
    }
}