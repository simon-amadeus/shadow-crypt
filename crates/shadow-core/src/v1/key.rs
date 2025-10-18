use std::mem;

/// Argon2id parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDerivationParams {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub key_size: u32,
}
impl KeyDerivationParams {
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32, key_size: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
            key_size,
        }
    }

    pub fn size() -> usize {
        mem::size_of::<u32>() * 4
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        let memory_cost = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let time_cost = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let parallelism = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let key_size = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        Some(Self {
            memory_cost,
            time_cost,
            parallelism,
            key_size,
        })
    }
}
