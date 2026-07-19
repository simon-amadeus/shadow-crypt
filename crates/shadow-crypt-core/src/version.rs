use crate::errors::HeaderError;

/// Magic bytes shared by every shadow file format version.
pub const MAGIC: [u8; 6] = *b"SHADOW";

/// Length of the magic-and-version preamble shared by every format version.
pub const PREAMBLE_LENGTH: usize = MAGIC.len() + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::V1 => "v1",
            Version::V2 => "v2",
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Version::V1 => 1,
            Version::V2 => 2,
        }
    }
}

impl TryFrom<u8> for Version {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Version::V1),
            2 => Ok(Version::V2),
            _ => Err(()),
        }
    }
}

/// Reads the magic-and-version preamble shared by all format versions.
///
/// Every shadow file starts with the 6 magic bytes followed by one version
/// byte; this lets callers pick the right version module without depending
/// on any of them.
pub fn read_file_version(bytes: &[u8]) -> Result<Version, HeaderError> {
    if bytes.len() < PREAMBLE_LENGTH {
        return Err(HeaderError::InsufficientBytes);
    }
    if bytes[..MAGIC.len()] != MAGIC {
        return Err(HeaderError::InvalidData);
    }
    Version::try_from(bytes[MAGIC.len()]).map_err(|_| HeaderError::InvalidData)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_as_str() {
        assert_eq!(Version::V1.as_str(), "v1");
        assert_eq!(Version::V2.as_str(), "v2");
    }

    #[test]
    fn test_version_as_u8() {
        assert_eq!(Version::V1.as_u8(), 1);
        assert_eq!(Version::V2.as_u8(), 2);
    }

    #[test]
    fn test_try_from_u8() {
        assert_eq!(Version::try_from(1), Ok(Version::V1));
        assert_eq!(Version::try_from(2), Ok(Version::V2));
        assert!(Version::try_from(0).is_err());
        assert!(Version::try_from(3).is_err());
    }

    #[test]
    fn test_read_file_version() {
        let mut bytes = b"SHADOW".to_vec();
        bytes.push(2);
        assert_eq!(read_file_version(&bytes).unwrap(), Version::V2);

        bytes[6] = 1;
        assert_eq!(read_file_version(&bytes).unwrap(), Version::V1);

        bytes[6] = 99;
        assert!(read_file_version(&bytes).is_err());

        assert!(read_file_version(b"SHADO").is_err());
        assert!(read_file_version(b"NOTSHD\x01").is_err());
    }
}
