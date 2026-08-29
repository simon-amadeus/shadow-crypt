//! Byte-soup fuzzing of the v2 header parser: must never panic, and a
//! successful parse must re-serialize and re-parse consistently.
#![no_main]

use libfuzzer_sys::fuzz_target;
use shadow_crypt_core::v2::header::FileHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = FileHeader::try_deserialize(data) {
        let serialized = header.serialize();
        let reparsed = FileHeader::try_deserialize(&serialized)
            .expect("re-serialized header must parse");
        assert_eq!(reparsed.serialize(), serialized);
    }
});
