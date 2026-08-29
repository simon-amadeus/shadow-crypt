//! The shadow archive payload format: a directory tree serialized as one
//! byte stream.
//!
//! An archive travels as the *content* of an encrypted file whose metadata
//! envelope marks it as [`crate::file::ContentKind::Archive`], so it
//! inherits the container format's encryption, authentication, and
//! streaming. This module defines only the plaintext payload layout and is
//! deliberately independent of the format versions: the layout carries its
//! own magic and version byte and can be reused by future container
//! versions unchanged.
//!
//! Layout (all integers little endian):
//!
//! ```text
//! magic: "SHDWARC" + version byte 1        (8 bytes)
//! entries, each:
//!   entry_type: u8                          (1 = file, 2 = directory, 0 = end)
//!   for file/directory entries:
//!     path_len: u16, path: UTF-8            ('/'-separated relative path)
//!     flags: u8                             (bit 0 mtime, bit 1 mode)
//!     mtime_secs: i64, mtime_nanos: u32     (if flag)
//!     mode: u32                             (if flag)
//!   for file entries:
//!     content_len: u64, content bytes
//! terminator: entry_type 0; nothing may follow
//! ```
//!
//! Directory entries appear before their contents. Paths are validated on
//! both encode and parse: relative, '/'-separated, no `..` or `.` or empty
//! components, no backslashes.
//!
//! Encoding is a set of pure functions producing header bytes (the caller
//! interleaves raw file content); parsing is the incremental
//! [`ArchiveParser`], fed arbitrary byte pieces and drained of
//! [`ArchiveEvent`]s, so neither side ever needs the whole archive in
//! memory.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::{
    file::FileMetadata,
    memory::{SecureBytes, SecureString},
};

pub const MAGIC: [u8; 8] = *b"SHDWARC\x01";

const ENTRY_END: u8 = 0;
const ENTRY_FILE: u8 = 1;
const ENTRY_DIR: u8 = 2;

const FLAG_MTIME: u8 = 0b0000_0001;
const FLAG_MODE: u8 = 0b0000_0010;

/// Upper bound on an entry path, matching common filesystem limits.
pub const MAX_PATH_LEN: usize = 4096;

/// Errors from encoding or parsing an archive stream.
#[derive(Debug)]
pub enum ArchiveError {
    /// A path is empty, absolute, contains `..`/`.`/empty components or
    /// backslashes, or exceeds [`MAX_PATH_LEN`].
    InvalidPath,
    /// The stream is structurally malformed (bad magic, unknown entry type
    /// or flags, invalid field values).
    InvalidData,
    /// The stream ended before the terminator entry.
    Truncated,
    /// Data follows the terminator entry.
    TrailingData,
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveError::InvalidPath => write!(f, "Archive entry path is invalid"),
            ArchiveError::InvalidData => write!(f, "Archive stream is malformed"),
            ArchiveError::Truncated => write!(f, "Archive stream ended unexpectedly"),
            ArchiveError::TrailingData => write!(f, "Data present after the archive terminator"),
        }
    }
}

impl std::error::Error for ArchiveError {}

/// Validates a '/'-separated relative entry path.
pub fn validate_path(path: &str) -> Result<(), ArchiveError> {
    if path.is_empty() || path.len() > MAX_PATH_LEN || path.contains('\\') {
        return Err(ArchiveError::InvalidPath);
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(ArchiveError::InvalidPath);
        }
    }
    Ok(())
}

fn encode_entry_header(entry_type: u8, metadata: &FileMetadata) -> Result<Vec<u8>, ArchiveError> {
    let path = metadata.filename().as_str();
    validate_path(path)?;

    let mtime = metadata.mtime().map(systemtime_to_parts);

    let mut flags = 0u8;
    if mtime.is_some() {
        flags |= FLAG_MTIME;
    }
    if metadata.mode().is_some() {
        flags |= FLAG_MODE;
    }

    let mut bytes = Vec::with_capacity(1 + 2 + path.len() + 1 + 12 + 4);
    bytes.push(entry_type);
    bytes.extend_from_slice(&(path.len() as u16).to_le_bytes());
    bytes.extend_from_slice(path.as_bytes());
    bytes.push(flags);
    if let Some((secs, nanos)) = mtime {
        bytes.extend_from_slice(&secs.to_le_bytes());
        bytes.extend_from_slice(&nanos.to_le_bytes());
    }
    if let Some(mode) = metadata.mode() {
        bytes.extend_from_slice(&mode.to_le_bytes());
    }
    Ok(bytes)
}

/// Header bytes for a directory entry. `metadata.filename()` is the
/// directory's relative path.
pub fn encode_directory(metadata: &FileMetadata) -> Result<Vec<u8>, ArchiveError> {
    encode_entry_header(ENTRY_DIR, metadata)
}

/// Header bytes for a file entry; exactly `content_len` raw content bytes
/// must follow. `metadata.filename()` is the file's relative path.
pub fn encode_file(metadata: &FileMetadata, content_len: u64) -> Result<Vec<u8>, ArchiveError> {
    let mut bytes = encode_entry_header(ENTRY_FILE, metadata)?;
    bytes.extend_from_slice(&content_len.to_le_bytes());
    Ok(bytes)
}

/// The archive terminator entry.
pub fn encode_end() -> [u8; 1] {
    [ENTRY_END]
}

/// One parsed element of an archive stream, in stream order.
#[derive(Debug)]
pub enum ArchiveEvent {
    /// A directory entry; `metadata.filename()` is its relative path.
    Directory { metadata: FileMetadata },
    /// Start of a file entry of `size` content bytes; [`ArchiveEvent::FileData`]
    /// events follow, then [`ArchiveEvent::FileEnd`].
    FileStart { metadata: FileMetadata, size: u64 },
    /// A piece of the current file's content.
    FileData(SecureBytes),
    /// The current file's content is complete.
    FileEnd,
    /// The archive terminator was reached.
    End,
}

enum State {
    Magic,
    EntryType,
    EntryHeader { entry_type: u8 },
    FileContent { remaining: u64 },
    Finished,
}

/// Incremental archive parser: [`ArchiveParser::feed`] it byte pieces of any
/// size, then drain [`ArchiveParser::next_event`] until it returns `None`
/// (more input needed). Call [`ArchiveParser::finish`] after the last feed
/// to catch truncated streams. Buffered bytes are zeroized on drop.
pub struct ArchiveParser {
    buf: Zeroizing<Vec<u8>>,
    state: State,
}

impl ArchiveParser {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
            state: State::Magic,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Returns the next event, or `None` when more input is needed.
    pub fn next_event(&mut self) -> Result<Option<ArchiveEvent>, ArchiveError> {
        match self.state {
            State::Magic => {
                if self.buf.len() < MAGIC.len() {
                    return Ok(None);
                }
                if self.buf[..MAGIC.len()] != MAGIC {
                    return Err(ArchiveError::InvalidData);
                }
                self.consume(MAGIC.len());
                self.state = State::EntryType;
                self.next_event()
            }
            State::EntryType => {
                let Some(&entry_type) = self.buf.first() else {
                    return Ok(None);
                };
                self.consume(1);
                match entry_type {
                    ENTRY_END => {
                        self.state = State::Finished;
                        if !self.buf.is_empty() {
                            return Err(ArchiveError::TrailingData);
                        }
                        Ok(Some(ArchiveEvent::End))
                    }
                    ENTRY_FILE | ENTRY_DIR => {
                        self.state = State::EntryHeader { entry_type };
                        self.next_event()
                    }
                    _ => Err(ArchiveError::InvalidData),
                }
            }
            State::EntryHeader { entry_type } => {
                let Some((consumed, metadata, content_len)) =
                    try_parse_entry_header(&self.buf, entry_type)?
                else {
                    return Ok(None);
                };
                self.consume(consumed);
                if entry_type == ENTRY_DIR {
                    self.state = State::EntryType;
                    Ok(Some(ArchiveEvent::Directory { metadata }))
                } else {
                    self.state = State::FileContent {
                        remaining: content_len,
                    };
                    Ok(Some(ArchiveEvent::FileStart {
                        metadata,
                        size: content_len,
                    }))
                }
            }
            State::FileContent { remaining } => {
                if remaining == 0 {
                    self.state = State::EntryType;
                    return Ok(Some(ArchiveEvent::FileEnd));
                }
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let take = usize::try_from(remaining)
                    .unwrap_or(usize::MAX)
                    .min(self.buf.len());
                let data = SecureBytes::new(self.buf[..take].to_vec());
                self.consume(take);
                self.state = State::FileContent {
                    remaining: remaining - take as u64,
                };
                Ok(Some(ArchiveEvent::FileData(data)))
            }
            State::Finished => {
                if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(ArchiveError::TrailingData)
                }
            }
        }
    }

    /// Verifies the stream ended cleanly: terminator seen, no bytes left.
    pub fn finish(&self) -> Result<(), ArchiveError> {
        match self.state {
            State::Finished if self.buf.is_empty() => Ok(()),
            State::Finished => Err(ArchiveError::TrailingData),
            _ => Err(ArchiveError::Truncated),
        }
    }

    fn consume(&mut self, n: usize) {
        self.buf.drain(..n);
    }
}

/// Attempts to parse one entry header (without the type byte) from `buf`.
/// Returns `None` when more bytes are needed.
#[allow(clippy::type_complexity)]
fn try_parse_entry_header(
    buf: &[u8],
    entry_type: u8,
) -> Result<Option<(usize, FileMetadata, u64)>, ArchiveError> {
    let Some(path_len_bytes) = buf.get(0..2) else {
        return Ok(None);
    };
    let path_len = u16::from_le_bytes(path_len_bytes.try_into().unwrap()) as usize;
    if path_len > MAX_PATH_LEN {
        return Err(ArchiveError::InvalidPath);
    }

    let Some(&flags) = buf.get(2 + path_len) else {
        return Ok(None);
    };
    if flags & !(FLAG_MTIME | FLAG_MODE) != 0 {
        return Err(ArchiveError::InvalidData);
    }

    let mut total = 2 + path_len + 1;
    if flags & FLAG_MTIME != 0 {
        total += 12;
    }
    if flags & FLAG_MODE != 0 {
        total += 4;
    }
    if entry_type == ENTRY_FILE {
        total += 8;
    }
    if buf.len() < total {
        return Ok(None);
    }

    let path = std::str::from_utf8(&buf[2..2 + path_len]).map_err(|_| ArchiveError::InvalidPath)?;
    validate_path(path)?;

    let mut offset = 2 + path_len + 1;
    let mtime = if flags & FLAG_MTIME != 0 {
        let secs = i64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
        let nanos = u32::from_le_bytes(buf[offset + 8..offset + 12].try_into().unwrap());
        offset += 12;
        if nanos >= 1_000_000_000 {
            return Err(ArchiveError::InvalidData);
        }
        Some(parts_to_systemtime(secs, nanos).ok_or(ArchiveError::InvalidData)?)
    } else {
        None
    };
    let mode = if flags & FLAG_MODE != 0 {
        let mode = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
        offset += 4;
        Some(mode)
    } else {
        None
    };
    let content_len = if entry_type == ENTRY_FILE {
        u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
    } else {
        0
    };

    let metadata = FileMetadata::new(SecureString::new(path.to_string()), mtime, mode);
    Ok(Some((total, metadata, content_len)))
}

/// Splits a `SystemTime` into (seconds, nanoseconds) relative to the Unix
/// epoch, with pre-epoch times as negative seconds and nanos in `[0, 1e9)`.
/// Total for any `SystemTime`: the seconds saturate at the i64 range
/// (hundreds of billions of years out), so extreme timestamps can never
/// overflow — found by fuzzing with `mtime_secs = i64::MIN`.
fn systemtime_to_parts(t: SystemTime) -> (i64, u32) {
    let (secs, nanos): (i128, u32) = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs().into(), d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let (secs, nanos) = (i128::from(d.as_secs()), d.subsec_nanos());
            if nanos == 0 {
                (-secs, 0)
            } else {
                (-(secs + 1), 1_000_000_000 - nanos)
            }
        }
    };
    (secs.clamp(i64::MIN.into(), i64::MAX.into()) as i64, nanos)
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

    fn meta(path: &str) -> FileMetadata {
        FileMetadata::new(
            SecureString::new(path.to_string()),
            Some(UNIX_EPOCH + Duration::new(1_700_000_000, 42)),
            Some(0o644),
        )
    }

    /// Encodes a small archive: a directory, a file with content, an empty
    /// file, and the terminator.
    fn sample_archive() -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&encode_directory(&meta("sub")).unwrap());
        bytes.extend_from_slice(&encode_file(&meta("sub/a.txt"), 11).unwrap());
        bytes.extend_from_slice(b"hello world");
        bytes.extend_from_slice(&encode_file(&meta("empty.bin"), 0).unwrap());
        bytes.extend_from_slice(&encode_end());
        bytes
    }

    /// Feeds the archive in pieces of `piece_len` and collects all events.
    fn parse_in_pieces(bytes: &[u8], piece_len: usize) -> Result<Vec<String>, ArchiveError> {
        let mut parser = ArchiveParser::new();
        let mut events = Vec::new();
        let mut content = Vec::new();
        for piece in bytes.chunks(piece_len.max(1)) {
            parser.feed(piece);
            while let Some(event) = parser.next_event()? {
                match event {
                    ArchiveEvent::Directory { metadata } => {
                        events.push(format!("dir:{}", metadata.filename().as_str()));
                    }
                    ArchiveEvent::FileStart { metadata, size } => {
                        content.clear();
                        events.push(format!("file:{}:{}", metadata.filename().as_str(), size));
                    }
                    ArchiveEvent::FileData(data) => content.extend_from_slice(data.as_slice()),
                    ArchiveEvent::FileEnd => {
                        events.push(format!("data:{}", String::from_utf8_lossy(&content)));
                    }
                    ArchiveEvent::End => events.push("end".to_string()),
                }
            }
        }
        parser.finish()?;
        Ok(events)
    }

    #[test]
    fn round_trip_all_piece_sizes() {
        let bytes = sample_archive();
        // Byte-at-a-time up through whole-buffer feeds must all parse the same.
        for piece_len in [1, 2, 3, 7, 16, bytes.len()] {
            let events = parse_in_pieces(&bytes, piece_len).unwrap();
            assert_eq!(
                events,
                vec![
                    "dir:sub",
                    "file:sub/a.txt:11",
                    "data:hello world",
                    "file:empty.bin:0",
                    "data:",
                    "end",
                ],
                "piece_len {piece_len}"
            );
        }
    }

    #[test]
    fn entry_metadata_round_trips() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&encode_file(&meta("f"), 0).unwrap());
        bytes.extend_from_slice(&encode_end());

        let mut parser = ArchiveParser::new();
        parser.feed(&bytes);
        let Some(ArchiveEvent::FileStart { metadata, .. }) = parser.next_event().unwrap() else {
            panic!("expected FileStart");
        };
        assert_eq!(metadata.mtime(), meta("f").mtime());
        assert_eq!(metadata.mode(), Some(0o644));
    }

    #[test]
    fn empty_archive_round_trips() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&encode_end());
        assert_eq!(parse_in_pieces(&bytes, 1).unwrap(), vec!["end"]);
    }

    #[test]
    fn truncated_stream_is_detected() {
        let bytes = sample_archive();
        for len in 0..bytes.len() - 1 {
            assert!(
                parse_in_pieces(&bytes[..len], 64).is_err(),
                "accepted truncation at {len}"
            );
        }
    }

    #[test]
    fn trailing_data_is_detected() {
        let mut bytes = sample_archive();
        bytes.push(0);
        assert!(matches!(
            parse_in_pieces(&bytes, 64),
            Err(ArchiveError::TrailingData)
        ));
    }

    #[test]
    fn wrong_magic_is_detected() {
        let mut bytes = sample_archive();
        bytes[0] ^= 1;
        assert!(matches!(
            parse_in_pieces(&bytes, 64),
            Err(ArchiveError::InvalidData)
        ));
    }

    #[test]
    fn unknown_entry_type_is_detected() {
        let mut bytes = MAGIC.to_vec();
        bytes.push(9);
        assert!(matches!(
            parse_in_pieces(&bytes, 64),
            Err(ArchiveError::InvalidData)
        ));
    }

    #[test]
    fn evil_paths_are_rejected_on_encode_and_parse() {
        for path in [
            "",
            "..",
            "../etc/passwd",
            "a/../b",
            "/abs",
            "a//b",
            "a/./b",
            "a\\b",
            "a/",
        ] {
            assert!(
                encode_file(
                    &FileMetadata::new(SecureString::new(path.to_string()), None, None),
                    0
                )
                .is_err(),
                "encode accepted {path:?}"
            );

            // Hand-craft the same path into a stream to test the parse side.
            let mut bytes = MAGIC.to_vec();
            bytes.push(1);
            bytes.extend_from_slice(&(path.len() as u16).to_le_bytes());
            bytes.extend_from_slice(path.as_bytes());
            bytes.push(0); // flags
            bytes.extend_from_slice(&0u64.to_le_bytes());
            bytes.extend_from_slice(&encode_end());
            assert!(
                parse_in_pieces(&bytes, 64).is_err(),
                "parse accepted {path:?}"
            );
        }
    }

    #[test]
    fn valid_nested_path_is_accepted() {
        assert!(validate_path("a/b/c.txt").is_ok());
        assert!(validate_path("single").is_ok());
    }
}
