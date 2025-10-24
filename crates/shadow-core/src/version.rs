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
