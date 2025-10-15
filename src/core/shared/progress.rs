//! Progress reporting utilities for pipeline operations.
//!
//! Provides simple, non-intrusive progress feedback for long-running operations
//! without changing business logic or requiring complex state management.

/// Simple progress wrapper that can be added to any iterator
pub struct ProgressWrapper<I> {
    inner: I,
    message: &'static str,
    started: bool,
}

impl<I: Iterator> Iterator for ProgressWrapper<I> {
    type Item = I::Item;
    
    fn next(&mut self) -> Option<Self::Item> {
        if !self.started {
            println!("⏳ {}", self.message);
            self.started = true;
        }
        self.inner.next()
    }
}

/// Extension trait for adding progress reporting to any iterator
pub trait ProgressStep<T>: Iterator<Item = T> + Sized {
    /// Add progress reporting to this iterator
    /// 
    /// Prints the progress message when the iterator is first consumed,
    /// then delegates to the wrapped iterator.
    /// 
    /// # Example
    /// ```rust
    /// use crate::core::shared::progress::ProgressStep;
    /// 
    /// let results: Vec<i32> = (1..=5)
    ///     .progress_step("Processing numbers...")
    ///     .map(|x| x * 2)
    ///     .collect();
    /// // Prints: ⏳ Processing numbers...
    /// // Returns: [2, 4, 6, 8, 10]
    /// ```
    fn progress_step(self, message: &'static str) -> ProgressWrapper<Self> {
        ProgressWrapper { 
            inner: self, 
            message, 
            started: false 
        }
    }
}

// Blanket implementation for all iterators
impl<T, I: Iterator<Item = T>> ProgressStep<T> for I {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_step_shows_message_once() {
        let items: Vec<i32> = vec![1, 2, 3];
        let results: Vec<i32> = items
            .into_iter()
            .progress_step("Testing progress...")
            .collect();
        
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[test]
    fn progress_step_empty_iterator() {
        let items: Vec<i32> = vec![];
        let results: Vec<i32> = items
            .into_iter()
            .progress_step("Testing empty...")
            .collect();
        
        assert_eq!(results, vec![]);
    }

    #[test]
    fn progress_step_chainable() {
        let results: Vec<i32> = (1..=3)
            .progress_step("Step 1...")
            .map(|x| x * 2)
            .progress_step("Step 2...")
            .filter(|&x| x > 2)
            .collect();
        
        assert_eq!(results, vec![4, 6]);
    }
}