//! Fuzzing of the incremental archive parser: arbitrary bytes fed in
//! arbitrary piece sizes must never panic, and event sequences must stay
//! well-formed (FileData only between FileStart and FileEnd).
#![no_main]

use libfuzzer_sys::fuzz_target;
use shadow_crypt_core::archive::{ArchiveEvent, ArchiveParser};

fuzz_target!(|data: &[u8]| {
    // The first byte seeds the feed piece size so chunk-boundary handling
    // gets exercised across runs.
    let (seed, payload) = match data.split_first() {
        Some((s, rest)) => (*s as usize % 32 + 1, rest),
        None => return,
    };

    let mut parser = ArchiveParser::new();
    let mut in_file = false;
    let mut ended = false;

    for piece in payload.chunks(seed) {
        parser.feed(piece);
        loop {
            match parser.next_event() {
                Ok(Some(event)) => {
                    assert!(!ended, "no events may follow End");
                    match event {
                        ArchiveEvent::FileStart { .. } => {
                            assert!(!in_file);
                            in_file = true;
                        }
                        ArchiveEvent::FileData(_) => assert!(in_file),
                        ArchiveEvent::FileEnd => {
                            assert!(in_file);
                            in_file = false;
                        }
                        ArchiveEvent::Directory { .. } => assert!(!in_file),
                        ArchiveEvent::End => ended = true,
                    }
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
    let _ = parser.finish();
});
