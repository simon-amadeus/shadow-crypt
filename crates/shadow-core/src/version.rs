pub enum Version {
    V1,
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::V1 => "v1",
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Version::V1 => 1,
        }
    }
}

pub fn is_supported_version(version: u8) -> bool {
    matches!(version, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_as_str() {
        assert_eq!(Version::V1.as_str(), "v1");
    }

    #[test]
    fn test_version_as_u8() {
        assert_eq!(Version::V1.as_u8(), 1);
    }

    #[test]
    fn test_is_supported_version() {
        assert!(is_supported_version(1));
        assert!(!is_supported_version(0));
        assert!(!is_supported_version(2));
        assert!(!is_supported_version(255));
    }
}
