//! Byte-soup fuzzing of the v3 metadata envelope parser: must never panic,
//! and a successful parse must round-trip through serialize.
#![no_main]

use libfuzzer_sys::fuzz_target;
use shadow_crypt_core::v3::metadata;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = metadata::parse(data) {
        let serialized = metadata::serialize(&parsed).expect("parsed metadata must serialize");
        let reparsed = metadata::parse(serialized.as_slice())
            .expect("re-serialized envelope must parse");
        assert_eq!(reparsed.filename().as_str(), parsed.filename().as_str());
        assert_eq!(reparsed.mtime(), parsed.mtime());
        assert_eq!(reparsed.mode(), parsed.mode());
        assert_eq!(reparsed.kind(), parsed.kind());
    }
});
