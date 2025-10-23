use std::fmt::Display;

pub enum Algorithm {
    XChaCha20Poly1305,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::XChaCha20Poly1305 => write!(f, "XChaCha20-Poly1305"),
        }
    }
}
