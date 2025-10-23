use std::{path::PathBuf, time::Duration};

pub struct OutputFile {
    pub path: PathBuf,
    pub filename: String,
}

pub struct EncryptionReport {
    pub input_filename: String,
    pub output_filename: String,
    pub duration: Duration,
}
impl EncryptionReport {
    pub fn new(input_filename: String, output_filename: String, duration: Duration) -> Self {
        Self {
            input_filename,
            output_filename,
            duration,
        }
    }
}
