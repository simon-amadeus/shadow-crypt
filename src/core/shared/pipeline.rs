//! Pipeline combinators for functional composition with resilient error handling.

/// Extension trait for processing iterators with resilient error handling
pub trait ProcessContinue<T>: Iterator<Item = T> + Sized {
    /// Process all items, collecting successes and failures separately
    fn process_continue<S, F, E>(self, f: impl Fn(T) -> Result<S, E>) -> (Vec<S>, Vec<F>)
    where
        F: From<E>,
    {
        let mut successful = Vec::new();
        let mut failed = Vec::new();
        
        for item in self {
            match f(item) {
                Ok(success) => successful.push(success),
                Err(error) => failed.push(F::from(error)),
            }
        }
        
        (successful, failed)
    }
}

// Blanket implementation for all iterators
impl<T, I: Iterator<Item = T>> ProcessContinue<T> for I {}
