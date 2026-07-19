//! Guards for Argon2 parameters read from untrusted file headers.
//!
//! Every code path that derives a key from header-supplied parameters
//! (decryption and listing alike) must validate them here first, so a
//! crafted .shadow file cannot request an enormous allocation or an
//! excessive amount of CPU time.

use std::sync::{Condvar, Mutex};

use shadow_crypt_core::{
    errors::KeyDerivationError, memory::SecureKey, report::KeyDerivationReport,
};

use crate::errors::{WorkflowError, WorkflowResult};

/// Upper bounds for KDF parameters read from untrusted file headers.
/// These prevent a crafted file from causing OOM or excessive CPU use.
pub const MAX_KDF_MEMORY_KIB: u32 = 8 * 1024 * 1024; // 8 GiB
pub const MAX_KDF_ITERATIONS: u32 = 1_000;
pub const MAX_KDF_PARALLELISM: u32 = 256;
pub const MAX_KDF_KEY_SIZE: u8 = 64;

/// Validates KDF parameters taken from an untrusted file header.
///
/// Takes raw values rather than a version-specific params struct so that
/// every format version can use the same bounds.
pub fn validate_untrusted_kdf_params(
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    key_size: u8,
) -> WorkflowResult<()> {
    if memory_cost > MAX_KDF_MEMORY_KIB {
        return Err(WorkflowError::UserInput(format!(
            "KDF memory cost in file header is too large: {} KiB (max {} KiB)",
            memory_cost, MAX_KDF_MEMORY_KIB
        )));
    }
    if time_cost > MAX_KDF_ITERATIONS {
        return Err(WorkflowError::UserInput(format!(
            "KDF iteration count in file header is too large: {} (max {})",
            time_cost, MAX_KDF_ITERATIONS
        )));
    }
    if parallelism > MAX_KDF_PARALLELISM {
        return Err(WorkflowError::UserInput(format!(
            "KDF parallelism in file header is too large: {} (max {})",
            parallelism, MAX_KDF_PARALLELISM
        )));
    }
    if key_size > MAX_KDF_KEY_SIZE {
        return Err(WorkflowError::UserInput(format!(
            "KDF key size in file header is too large: {} bytes (max {})",
            key_size, MAX_KDF_KEY_SIZE
        )));
    }
    Ok(())
}

/// Derives a key from KDF parameters read out of an untrusted file header.
///
/// Validates the parameters against the bounds above and, only if they pass,
/// runs `derive` while holding a reservation against the global memory
/// budget. This is the single intended entry point for header-supplied
/// parameters: fusing the two steps makes it impossible to run an
/// unvalidated derivation from a crafted file.
///
/// Takes raw values rather than a version-specific params struct so that
/// every format version can use the same guard.
pub fn derive_key_from_untrusted_params(
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    key_size: u8,
    derive: impl FnOnce() -> Result<(SecureKey, KeyDerivationReport), KeyDerivationError>,
) -> WorkflowResult<SecureKey> {
    validate_untrusted_kdf_params(memory_cost, time_cost, parallelism, key_size)?;
    let (key, _) = with_kdf_memory_permit(memory_cost, derive)?;
    Ok(key)
}

/// Total Argon2 buffer memory allowed across all concurrent derivations.
///
/// Argon2 allocates its full memory cost per derivation, and files are
/// processed in parallel (one rayon thread per core). Without a cap, ten
/// production-profile files on a 10-core machine would hold ~10 GiB of
/// Argon2 buffers at once. The budget throttles concurrency by declared
/// memory cost instead of thread count, so cheap derivations still run
/// fully parallel.
pub const KDF_MEMORY_BUDGET_KIB: u64 = 4 * 1024 * 1024; // 4 GiB

/// Global gate shared by all workflows in the process.
static KDF_GATE: KdfGate = KdfGate::new(KDF_MEMORY_BUDGET_KIB);

/// Runs `f` (a key derivation) while holding a reservation of `cost_kib`
/// against the global memory budget, blocking until enough budget is free.
///
/// A cost larger than the whole budget is clamped to it, so an oversized
/// (but validated) derivation waits for exclusive use of the budget and
/// then runs alone rather than deadlocking.
pub fn with_kdf_memory_permit<T>(cost_kib: u32, f: impl FnOnce() -> T) -> T {
    let _permit = KDF_GATE.acquire(cost_kib as u64);
    f()
}

struct KdfGate {
    budget_kib: u64,
    in_use_kib: Mutex<u64>,
    released: Condvar,
}

impl KdfGate {
    const fn new(budget_kib: u64) -> Self {
        Self {
            budget_kib,
            in_use_kib: Mutex::new(0),
            released: Condvar::new(),
        }
    }

    fn acquire(&self, cost_kib: u64) -> KdfPermit<'_> {
        // Reserve at least 1 KiB so a zero-cost caller still participates,
        // and never more than the budget so acquisition always succeeds.
        let cost_kib = cost_kib.clamp(1, self.budget_kib);
        let mut in_use = self.in_use_kib.lock().unwrap_or_else(|e| e.into_inner());
        while *in_use + cost_kib > self.budget_kib {
            in_use = self
                .released
                .wait(in_use)
                .unwrap_or_else(|e| e.into_inner());
        }
        *in_use += cost_kib;
        KdfPermit {
            gate: self,
            cost_kib,
        }
    }
}

struct KdfPermit<'a> {
    gate: &'a KdfGate,
    cost_kib: u64,
}

impl Drop for KdfPermit<'_> {
    fn drop(&mut self) {
        let mut in_use = self
            .gate
            .in_use_kib
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *in_use -= self.cost_kib;
        drop(in_use);
        self.gate.released.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_kdf_params_accepted() {
        assert!(validate_untrusted_kdf_params(1024, 1, 1, 32).is_ok());
    }

    #[test]
    fn test_memory_cost_too_large() {
        assert!(validate_untrusted_kdf_params(MAX_KDF_MEMORY_KIB + 1, 1, 1, 32).is_err());
    }

    #[test]
    fn test_memory_cost_at_limit_accepted() {
        assert!(validate_untrusted_kdf_params(MAX_KDF_MEMORY_KIB, 1, 1, 32).is_ok());
    }

    #[test]
    fn test_iterations_too_large() {
        assert!(validate_untrusted_kdf_params(1024, MAX_KDF_ITERATIONS + 1, 1, 32).is_err());
    }

    #[test]
    fn test_parallelism_too_large() {
        assert!(validate_untrusted_kdf_params(1024, 1, MAX_KDF_PARALLELISM + 1, 32).is_err());
    }

    #[test]
    fn test_key_size_too_large() {
        assert!(validate_untrusted_kdf_params(1024, 1, 1, MAX_KDF_KEY_SIZE + 1).is_err());
    }

    #[test]
    fn test_gate_allows_cost_within_budget() {
        let gate = KdfGate::new(100);
        let permit = gate.acquire(60);
        assert_eq!(*gate.in_use_kib.lock().unwrap(), 60);
        drop(permit);
        assert_eq!(*gate.in_use_kib.lock().unwrap(), 0);
    }

    #[test]
    fn test_gate_clamps_oversized_cost_to_budget() {
        let gate = KdfGate::new(100);
        // A cost above the budget must not deadlock: it is clamped and runs alone.
        let permit = gate.acquire(1_000_000);
        assert_eq!(*gate.in_use_kib.lock().unwrap(), 100);
        drop(permit);
    }

    #[test]
    fn test_gate_zero_cost_still_reserves() {
        let gate = KdfGate::new(100);
        let permit = gate.acquire(0);
        assert_eq!(*gate.in_use_kib.lock().unwrap(), 1);
        drop(permit);
    }

    #[test]
    fn test_gate_limits_concurrent_memory_use() {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };

        // Budget fits exactly two concurrent 50-KiB permits.
        let gate = Arc::new(KdfGate::new(100));
        let active = Arc::new(AtomicU64::new(0));
        let max_active = Arc::new(AtomicU64::new(0));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let gate = Arc::clone(&gate);
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                std::thread::spawn(move || {
                    let _permit = gate.acquire(50);
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    active.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert!(max_active.load(Ordering::SeqCst) <= 2);
        assert_eq!(*gate.in_use_kib.lock().unwrap(), 0);
    }

    #[test]
    fn test_with_kdf_memory_permit_returns_value() {
        let result = with_kdf_memory_permit(1024, || 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_production_params_accepted() {
        let params = shadow_crypt_core::v1::key::KeyDerivationParams::production_defaults();
        assert!(
            validate_untrusted_kdf_params(
                params.memory_cost,
                params.time_cost,
                params.parallelism,
                params.key_size
            )
            .is_ok()
        );
    }
}
