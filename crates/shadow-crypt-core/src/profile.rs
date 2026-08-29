/// Named key-derivation cost levels. Each format version maps a profile to
/// its own concrete Argon2id parameters (see the per-version `key` modules);
/// the numbers below describe the current write format (v3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// The default: the OWASP Password Storage Cheat Sheet's recommended
    /// Argon2id configuration with the highest memory hardness of the
    /// equivalent set — 46 MiB memory, 1 iteration, parallelism 1. Fast
    /// enough for batches and small machines.
    Standard,
    /// Maximum-cost derivation for high-value archives: 1 GiB memory,
    /// 10 iterations, parallelism 4. Needs at least 1 GiB of free RAM and
    /// takes seconds per file.
    Paranoid,
    /// For automated tests only: 1 MiB memory, 1 iteration. Insecure, and
    /// password strength checks are skipped.
    Test,
}
