// shadow-core/src/algorithms/argon2/profiles.rs
// Argon2-specific parameter configurations

use crate::security::SecurityProfile;
use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2 parameter configurations for different security profiles
pub struct Argon2Config;

impl Argon2Config {
    /// Get Argon2 parameters for the given security profile
    ///
    /// Returns properly configured Argon2 parameters that match the
    /// security requirements for each profile.
    ///
    /// # Panics
    ///
    /// Panics if the hardcoded parameters are invalid (should never happen
    /// in practice as these are well-tested parameter combinations).
    pub fn params(profile: SecurityProfile) -> Params {
        match profile {
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

    /// Create a configured Argon2 instance for the given security profile
    ///
    /// Returns an Argon2 instance using Argon2id algorithm with parameters
    /// appropriate for this security profile.
    pub fn create_argon2(profile: SecurityProfile) -> Argon2<'static> {
        let params = Self::params(profile);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_instance_creation() {
        let _test_argon2 = Argon2Config::create_argon2(SecurityProfile::Test);
        let _prod_argon2 = Argon2Config::create_argon2(SecurityProfile::Production);

        // Verify they're different instances with different parameters
        let test_params = Argon2Config::params(SecurityProfile::Test);
        let prod_params = Argon2Config::params(SecurityProfile::Production);

        assert_ne!(test_params.m_cost(), prod_params.m_cost());
        assert_ne!(test_params.t_cost(), prod_params.t_cost());
    }
}
