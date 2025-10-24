use std::io::Read;

use shadow_core::memory::SecureBytes;

use crate::errors::WorkflowResult;

pub fn read_n_bytes_from_file(path: &std::path::Path, n: usize) -> WorkflowResult<SecureBytes> {
    let f = std::fs::File::open(path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(n);
    f.take(n as u64).read_exact(buffer.as_mut_slice())?;

    Ok(SecureBytes::new(buffer))
}
