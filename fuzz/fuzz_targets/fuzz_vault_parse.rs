//! Byte-soup fuzzing of the version-dispatching vault parser: must never
//! panic on any input, whatever version byte it claims.
#![no_main]

use libfuzzer_sys::fuzz_target;
use shadow_crypt_core::vault::ParsedFile;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = ParsedFile::parse(data) {
        // Cheap accessors must also be panic-free on parsed garbage.
        let _ = parsed.version();
        let _ = parsed.algorithm();
        let _ = parsed.header_length();
        let _ = parsed.kdf_request();
    }
});
