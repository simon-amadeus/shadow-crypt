use std::time::Duration;

use shadow_core::algorithm::Algorithm;

pub struct CryptoReport {
    pub input_filename: String,
    pub output_filename: String,
    pub duration: Duration,
    pub algorithm: Algorithm,
}
impl CryptoReport {
    pub fn new(
        input_filename: String,
        output_filename: String,
        duration: Duration,
        algorithm: Algorithm,
    ) -> Self {
        Self {
            input_filename,
            output_filename,
            duration,
            algorithm,
        }
    }
}
