//! Plaintext layout of the encrypted metadata envelope.
//!
//! The envelope is serialized, then AEAD-encrypted under the metadata domain
//! and stored in the header. Layout (little endian):
//!
//! | field        | size     | present               |
//! |--------------|----------|-----------------------|
//! | flags        | 1 byte   | always                |
//! | filename_len | 2 bytes  | always                |
//! | filename     | variable | always (UTF-8)        |
//! | mtime_secs   | 8 bytes  | flags bit 0 (signed)  |
//! | mtime_nanos  | 4 bytes  | flags bit 0           |
//! | mode         | 4 bytes  | flags bit 1           |
//!
//! Trailing unknown bytes are rejected: this layout is fixed for the v3
//! format, and any extension is a new format version.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    errors::{FileError, HeaderError},
    file::FileMetadata,
    memory::{SecureBytes, SecureString},
};

const FLAG_MTIME: u8 = 0b0000_0001;
const FLAG_MODE: u8 = 0b0000_0010;

/// Largest serialized envelope that still fits the header's u16 ciphertext
/// length field once the 16-byte AEAD tag is added.
const MAX_ENVELOPE_LEN: usize = u16::MAX as usize - 16;

/// Serializes a metadata envelope. Fails with
/// [`HeaderError::MetadataTooLong`] when the filename pushes the envelope
/// past what the header can hold.
pub fn serialize(metadata: &FileMetadata) -> Result<SecureBytes, HeaderError> {
    let filename = metadata.filename().as_str().as_bytes();
    if u16::try_from(filename.len()).is_err() {
        return Err(HeaderError::MetadataTooLong);
    }

    let mtime = metadata.mtime().map(systemtime_to_parts);

    let mut flags = 0u8;
    if mtime.is_some() {
        flags |= FLAG_MTIME;
    }
    if metadata.mode().is_some() {
        flags |= FLAG_MODE;
    }

    let mut envelope = Vec::with_capacity(1 + 2 + filename.len() + 12 + 4);
    envelope.push(flags);
    envelope.extend_from_slice(&(filename.len() as u16).to_le_bytes());
    envelope.extend_from_slice(filename);
    if let Some((secs, nanos)) = mtime {
        envelope.extend_from_slice(&secs.to_le_bytes());
        envelope.extend_from_slice(&nanos.to_le_bytes());
    }
    if let Some(mode) = metadata.mode() {
        envelope.extend_from_slice(&mode.to_le_bytes());
    }

    if envelope.len() > MAX_ENVELOPE_LEN {
        return Err(HeaderError::MetadataTooLong);
    }
    Ok(SecureBytes::new(envelope))
}

/// Parses a decrypted metadata envelope. Any structural mismatch (bad
/// lengths, unknown flags, trailing bytes, invalid UTF-8 filename) is
/// [`FileError::InvalidMetadata`].
pub fn parse(envelope: &[u8]) -> Result<FileMetadata, FileError> {
    let err = || FileError::InvalidMetadata;

    let (&flags, rest) = envelope.split_first().ok_or_else(err)?;
    if flags & !(FLAG_MTIME | FLAG_MODE) != 0 {
        return Err(err());
    }

    let (len_bytes, rest) = rest.split_at_checked(2).ok_or_else(err)?;
    let filename_len = u16::from_le_bytes(len_bytes.try_into().map_err(|_| err())?) as usize;
    let (filename_bytes, rest) = rest.split_at_checked(filename_len).ok_or_else(err)?;
    let filename = std::str::from_utf8(filename_bytes).map_err(|_| err())?;

    let (mtime, rest) = if flags & FLAG_MTIME != 0 {
        let (secs_bytes, rest) = rest.split_at_checked(8).ok_or_else(err)?;
        let (nanos_bytes, rest) = rest.split_at_checked(4).ok_or_else(err)?;
        let secs = i64::from_le_bytes(secs_bytes.try_into().map_err(|_| err())?);
        let nanos = u32::from_le_bytes(nanos_bytes.try_into().map_err(|_| err())?);
        if nanos >= 1_000_000_000 {
            return Err(err());
        }
        (
            Some(parts_to_systemtime(secs, nanos).ok_or_else(err)?),
            rest,
        )
    } else {
        (None, rest)
    };

    let (mode, rest) = if flags & FLAG_MODE != 0 {
        let (mode_bytes, rest) = rest.split_at_checked(4).ok_or_else(err)?;
        let mode = u32::from_le_bytes(mode_bytes.try_into().map_err(|_| err())?);
        (Some(mode), rest)
    } else {
        (None, rest)
    };

    if !rest.is_empty() {
        return Err(err());
    }

    Ok(FileMetadata::new(
        SecureString::new(filename.to_string()),
        mtime,
        mode,
    ))
}

/// Splits a `SystemTime` into (seconds, nanoseconds) relative to the Unix
/// epoch, with pre-epoch times as negative seconds and nanos in `[0, 1e9)`.
fn systemtime_to_parts(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let (secs, nanos) = (d.as_secs() as i64, d.subsec_nanos());
            if nanos == 0 {
                (-secs, 0)
            } else {
                (-(secs + 1), 1_000_000_000 - nanos)
            }
        }
    }
}

fn parts_to_systemtime(secs: i64, nanos: u32) -> Option<SystemTime> {
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(secs as u64, nanos))
    } else if nanos == 0 {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_sub(Duration::new(
            (secs + 1).unsigned_abs(),
            1_000_000_000 - nanos,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(filename: &str, mtime: Option<SystemTime>, mode: Option<u32>) -> FileMetadata {
        FileMetadata::new(SecureString::new(filename.to_string()), mtime, mode)
    }

    fn round_trip(metadata: &FileMetadata) -> FileMetadata {
        parse(serialize(metadata).unwrap().as_slice()).unwrap()
    }

    #[test]
    fn round_trip_all_fields() {
        let mtime = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        let parsed = round_trip(&meta("café.txt", Some(mtime), Some(0o644)));

        assert_eq!(parsed.filename().as_str(), "café.txt");
        assert_eq!(parsed.mtime(), Some(mtime));
        assert_eq!(parsed.mode(), Some(0o644));
    }

    #[test]
    fn round_trip_filename_only() {
        let parsed = round_trip(&meta("a.txt", None, None));
        assert_eq!(parsed.filename().as_str(), "a.txt");
        assert_eq!(parsed.mtime(), None);
        assert_eq!(parsed.mode(), None);
    }

    #[test]
    fn round_trip_pre_epoch_mtime() {
        let mtime = UNIX_EPOCH - Duration::new(100, 250_000_000);
        let parsed = round_trip(&meta("old.txt", Some(mtime), None));
        assert_eq!(parsed.mtime(), Some(mtime));
    }

    #[test]
    fn unknown_flags_rejected() {
        let mut envelope = serialize(&meta("a", None, None))
            .unwrap()
            .as_slice()
            .to_vec();
        envelope[0] |= 0b1000_0000;
        assert!(parse(&envelope).is_err());
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut envelope = serialize(&meta("a", None, None))
            .unwrap()
            .as_slice()
            .to_vec();
        envelope.push(0);
        assert!(parse(&envelope).is_err());
    }

    #[test]
    fn truncated_envelope_rejected() {
        let envelope = serialize(&meta("abcdef", None, Some(0o600)))
            .unwrap()
            .as_slice()
            .to_vec();
        for len in 0..envelope.len() {
            assert!(parse(&envelope[..len]).is_err(), "accepted prefix {len}");
        }
    }

    #[test]
    fn invalid_utf8_filename_rejected() {
        // flags=0, filename_len=2, invalid UTF-8 bytes
        let envelope = [0u8, 2, 0, 0xff, 0xfe];
        assert!(parse(&envelope).is_err());
    }

    #[test]
    fn oversized_filename_rejected() {
        let long = "x".repeat(u16::MAX as usize + 1);
        assert!(matches!(
            serialize(&meta(&long, None, None)),
            Err(HeaderError::MetadataTooLong)
        ));
    }
}
