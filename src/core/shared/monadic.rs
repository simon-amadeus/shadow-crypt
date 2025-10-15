//! Monadic pipeline combinators for resilient functional composition.
//!
//! This module provides true monadic composition capabilities that enable
//! fluent, chainable operations with comprehensive error handling. Unlike
//! discrete step processing with early termination, monadic pipelines
//! continue processing despite individual failures while collecting all
//! results for comprehensive reporting.
//!
//! # Core Concepts
//!
//! - **PipelineItem<T, E>**: Monadic wrapper that flows through the pipeline
//! - **PipelineIterator<I, T, E>**: Container providing chainable combinators
//! - **Error Resilience**: Individual failures don't halt the entire pipeline
//! - **Progress Integration**: Non-intrusive progress reporting throughout
//!
//! # Usage Example
//!
//! ```rust
//! let (successes, failures) = input_data
//!     .into_iter()
//!     .pipeline()
//!     .flat_map_continue(expand_item)
//!     .filter_continue(validate_item)
//!     .map_continue(transform_item)
//!     .progress_step("Processing complete")
//!     .collect_results();
//! ```

use std::collections::HashMap;

// ============================================================================
// CORE MONADIC TYPES
// ============================================================================

/// Wrapper type that flows through the monadic pipeline.
/// 
/// This is the fundamental monadic type that carries either successful values
/// or error states through the processing chain. Unlike Result<T, E>, this
/// type is designed to flow through iterators and accumulate all failures
/// rather than short-circuiting on the first error.
#[derive(Debug, Clone, PartialEq)]
pub enum PipelineItem<T, E> {
    /// Successful value that can be processed by subsequent pipeline steps
    Success(T),
    /// Error that flows through unchanged, preserving failure context
    Failure(E),
}

impl<T, E> PipelineItem<T, E> {
    /// Create a new successful pipeline item.
    pub fn new_success(value: T) -> Self {
        Self::Success(value)
    }
    
    /// Create a new failed pipeline item.
    pub fn new_failure(error: E) -> Self {
        Self::Failure(error)
    }
    
    /// Check if this item represents a success.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }
    
    /// Check if this item represents a failure.
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failure(_))
    }
    
    /// Convert to Option<T>, discarding any error.
    pub fn ok(self) -> Option<T> {
        match self {
            Self::Success(value) => Some(value),
            Self::Failure(_) => None,
        }
    }
    
    /// Convert to Option<E>, discarding any success.
    pub fn err(self) -> Option<E> {
        match self {
            Self::Success(_) => None,
            Self::Failure(error) => Some(error),
        }
    }
}

impl<T, E> From<Result<T, E>> for PipelineItem<T, E> {
    fn from(result: Result<T, E>) -> Self {
        match result {
            Ok(value) => Self::Success(value),
            Err(error) => Self::Failure(error),
        }
    }
}

impl<T, E> From<PipelineItem<T, E>> for Result<T, E> {
    fn from(item: PipelineItem<T, E>) -> Self {
        match item {
            PipelineItem::Success(value) => Ok(value),
            PipelineItem::Failure(error) => Err(error),
        }
    }
}

// ============================================================================
// MONADIC ITERATOR CONTAINER
// ============================================================================

/// Iterator wrapper that provides monadic combinators.
/// 
/// This type wraps any iterator of PipelineItem<T, E> and provides chainable
/// monadic operations. It serves as the foundation for fluent pipeline
/// composition while maintaining type safety and error handling.
pub struct PipelineIterator<I, T, E> 
where
    I: Iterator<Item = PipelineItem<T, E>>,
{
    inner: I,
}

impl<I, T, E> PipelineIterator<I, T, E>
where
    I: Iterator<Item = PipelineItem<T, E>>,
{
    /// Create a new pipeline iterator wrapper.
    pub fn new(iter: I) -> Self {
        Self { inner: iter }
    }
}

impl<I, T, E> Iterator for PipelineIterator<I, T, E>
where
    I: Iterator<Item = PipelineItem<T, E>>,
{
    type Item = PipelineItem<T, E>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

// ============================================================================
// CORE MONADIC COMBINATORS
// ============================================================================

impl<I, T, E> PipelineIterator<I, T, E>
where
    I: Iterator<Item = PipelineItem<T, E>>,
{
    /// Monadic bind: transforms each success and flattens the results.
    /// 
    /// This is the fundamental monadic operation (>>=) that allows composing
    /// operations that may produce multiple outputs or fail. Each successful
    /// value is transformed by the function, which returns an iterator of
    /// results. All results are flattened into a single stream. Failures
    /// flow through unchanged.
    /// 
    /// # Arguments
    /// 
    /// * `f` - Function that transforms success values into iterators of results
    /// 
    /// # Example
    /// 
    /// ```rust
    /// // Expand each pattern into multiple file paths
    /// iterator.flat_map_continue(|pattern| expand_glob_pattern(&pattern))
    /// ```
    pub fn flat_map_continue<U, F, J>(
        self,
        f: F,
    ) -> PipelineIterator<impl Iterator<Item = PipelineItem<U, E>>, U, E>
    where
        F: Fn(T) -> J,
        J: IntoIterator<Item = Result<U, E>>,
    {
        let mapped = self.inner.flat_map(move |item| {
            match item {
                PipelineItem::Success(value) => {
                    f(value)
                        .into_iter()
                        .map(|result| match result {
                            Ok(success) => PipelineItem::Success(success),
                            Err(error) => PipelineItem::Failure(error),
                        })
                        .collect::<Vec<_>>()
                        .into_iter()
                }
                PipelineItem::Failure(error) => {
                    vec![PipelineItem::Failure(error)].into_iter()
                }
            }
        });
        
        PipelineIterator::new(mapped)
    }

    /// Monadic functor: transforms each success value.
    /// 
    /// This operation (fmap) applies a transformation function to each
    /// successful value in the pipeline. If the transformation succeeds,
    /// the new value continues through the pipeline. If it fails, the
    /// error is captured and flows through as a failure. Existing failures
    /// flow through unchanged.
    /// 
    /// # Arguments
    /// 
    /// * `f` - Function that transforms success values, potentially failing
    /// 
    /// # Example
    /// 
    /// ```rust
    /// // Transform file paths into metadata
    /// iterator.map_continue(|path| read_file_metadata(&path))
    /// ```
    pub fn map_continue<U, F>(
        self,
        f: F,
    ) -> PipelineIterator<impl Iterator<Item = PipelineItem<U, E>>, U, E>
    where
        F: Fn(T) -> Result<U, E>,
    {
        let mapped = self.inner.map(move |item| {
            match item {
                PipelineItem::Success(value) => {
                    match f(value) {
                        Ok(new_value) => PipelineItem::Success(new_value),
                        Err(error) => PipelineItem::Failure(error),
                    }
                }
                PipelineItem::Failure(error) => PipelineItem::Failure(error),
            }
        });
        
        PipelineIterator::new(mapped)
    }

    /// Monadic filter: keeps only successes that match predicate.
    /// 
    /// This operation filters the pipeline, keeping only successful values
    /// that satisfy the predicate. Values that don't match are filtered out
    /// (removed from the stream). If the predicate evaluation fails, that
    /// becomes a pipeline failure. Existing failures flow through unchanged.
    /// 
    /// # Arguments
    /// 
    /// * `predicate` - Function that tests success values, potentially failing
    /// 
    /// # Example
    /// 
    /// ```rust
    /// // Keep only regular files
    /// iterator.filter_continue(|path| is_regular_file(path))
    /// ```
    pub fn filter_continue<F>(
        self,
        predicate: F,
    ) -> PipelineIterator<impl Iterator<Item = PipelineItem<T, E>>, T, E>
    where
        F: Fn(&T) -> Result<bool, E>,
    {
        let filtered = self.inner.filter_map(move |item| {
            match item {
                PipelineItem::Success(value) => {
                    match predicate(&value) {
                        Ok(true) => Some(PipelineItem::Success(value)),
                        Ok(false) => None, // Filter out
                        Err(error) => Some(PipelineItem::Failure(error)),
                    }
                }
                PipelineItem::Failure(error) => Some(PipelineItem::Failure(error)),
            }
        });
        
        PipelineIterator::new(filtered)
    }
}

// ============================================================================
// COLLECTION AND PROGRESS METHODS
// ============================================================================

impl<I, T, E> PipelineIterator<I, T, E>
where
    I: Iterator<Item = PipelineItem<T, E>>,
{
    /// Collect all results, separating successes from failures.
    /// 
    /// This terminal operation consumes the pipeline iterator and separates
    /// all successful values from all failures. This enables comprehensive
    /// error reporting while still processing all possible items.
    /// 
    /// # Returns
    /// 
    /// A tuple of (successes, failures) where each Vec contains all items
    /// of that type encountered during pipeline processing.
    pub fn collect_results(self) -> (Vec<T>, Vec<E>) {
        let mut successes = Vec::new();
        let mut failures = Vec::new();
        
        for item in self.inner {
            match item {
                PipelineItem::Success(value) => successes.push(value),
                PipelineItem::Failure(error) => failures.push(error),
            }
        }
        
        (successes, failures)
    }

    /// Add custom progress reporting to the pipeline.
    /// 
    /// This operation adds a side-effect function that is called for each
    /// item flowing through the pipeline. The function receives a reference
    /// to the item and can perform logging, progress updates, or other
    /// monitoring without affecting the pipeline flow.
    /// 
    /// # Arguments
    /// 
    /// * `progress_fn` - Function called for each pipeline item
    pub fn with_progress<F>(
        self,
        progress_fn: F,
    ) -> PipelineIterator<impl Iterator<Item = PipelineItem<T, E>>, T, E>
    where
        F: Fn(&PipelineItem<T, E>),
    {
        let with_progress = self.inner.map(move |item| {
            progress_fn(&item);
            item
        });
        
        PipelineIterator::new(with_progress)
    }
    
    /// Convenience method for standard progress reporting.
    /// 
    /// This provides a simple way to add step-by-step progress reporting
    /// to the pipeline. It prints success/failure counts and step names
    /// to help with debugging and user feedback.
    /// 
    /// # Arguments
    /// 
    /// * `name` - Name of the processing step for progress messages
    pub fn progress_step(
        self, 
        name: &str
    ) -> PipelineIterator<impl Iterator<Item = PipelineItem<T, E>>, T, E>
    where
        T: Clone,
        E: Clone,
    {
        let step_name = name.to_string();
        self.with_progress(move |item| {
            match item {
                PipelineItem::Success(_) => {
                    println!("✓ {}: Success", step_name);
                }
                PipelineItem::Failure(_) => {
                    println!("✗ {}: Failure", step_name);
                }
            }
        })
    }
}

// ============================================================================
// PIPELINE ENTRY POINT TRAIT
// ============================================================================

/// Trait to convert standard iterators into monadic pipelines.
/// 
/// This trait provides the entry point for monadic pipeline processing
/// by adding a `.pipeline()` method to any iterator. It automatically
/// wraps values in PipelineItem::Success to start the monadic chain.
pub trait Pipeline<T>: Iterator<Item = T> + Sized {
    /// Convert a standard iterator into a monadic pipeline.
    /// 
    /// This method wraps each item in the iterator with PipelineItem::Success
    /// to begin monadic processing. From this point, you can chain monadic
    /// combinators like flat_map_continue, map_continue, and filter_continue.
    /// 
    /// # Example
    /// 
    /// ```rust
    /// let results = vec!["file1", "file2", "file3"]
    ///     .into_iter()
    ///     .pipeline()
    ///     .map_continue(|path| process_file(path))
    ///     .collect_results();
    /// ```
    fn pipeline<E>(self) -> PipelineIterator<impl Iterator<Item = PipelineItem<T, E>>, T, E> {
        let pipeline_items = self.map(PipelineItem::new_success);
        PipelineIterator::new(pipeline_items)
    }
}

// Implement Pipeline for all iterators
impl<T, I> Pipeline<T> for I where I: Iterator<Item = T> {}

// ============================================================================
// PIPELINE FAILURE TYPE
// ============================================================================

/// Enhanced error type for pipeline failures with context.
/// 
/// This type extends basic error information with step context and
/// additional metadata to help with debugging and error reporting
/// in complex pipeline operations.
#[derive(Debug, Clone)]
pub struct PipelineFailure {
    /// Name of the pipeline step where the failure occurred
    pub step: String,
    /// The underlying error that caused the failure
    pub error: String,
    /// Additional context information for debugging
    pub context: HashMap<String, String>,
}

impl PipelineFailure {
    /// Create a new pipeline failure.
    /// 
    /// # Arguments
    /// 
    /// * `step` - Name of the pipeline step
    /// * `error` - Description of the error
    pub fn new(step: &str, error: &str) -> Self {
        Self {
            step: step.to_string(),
            error: error.to_string(),
            context: HashMap::new(),
        }
    }
    
    /// Add context information to the failure.
    /// 
    /// # Arguments
    /// 
    /// * `key` - Context key
    /// * `value` - Context value
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

impl std::fmt::Display for PipelineFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pipeline failure in step '{}': {}", self.step, self.error)?;
        
        if !self.context.is_empty() {
            write!(f, " (context: ")?;
            let context_items: Vec<String> = self.context
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            write!(f, "{})", context_items.join(", "))?;
        }
        
        Ok(())
    }
}

impl std::error::Error for PipelineFailure {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_item_creation() {
        let success: PipelineItem<i32, &str> = PipelineItem::new_success(42);
        let failure: PipelineItem<i32, &str> = PipelineItem::new_failure("error");
        
        assert!(success.is_success());
        assert!(!success.is_failure());
        assert!(!failure.is_success());
        assert!(failure.is_failure());
    }

    #[test]
    fn test_pipeline_item_conversion() {
        let result_ok: Result<i32, &str> = Ok(42);
        let result_err: Result<i32, &str> = Err("error");
        
        let item_from_ok = PipelineItem::from(result_ok);
        let item_from_err = PipelineItem::from(result_err);
        
        assert!(item_from_ok.is_success());
        assert!(item_from_err.is_failure());
    }

    #[test]
    fn test_map_continue() {
        let items = vec![
            PipelineItem::new_success(1),
            PipelineItem::new_success(2),
            PipelineItem::new_failure("error"),
            PipelineItem::new_success(3),
        ];
        
        let (successes, failures): (Vec<_>, Vec<_>) = PipelineIterator::new(items.into_iter())
            .map_continue(|x| if x % 2 == 0 { Ok(x * 2) } else { Err("odd number") })
            .collect_results();
        
        assert_eq!(successes, vec![4]); // Only 2 * 2 = 4
        assert_eq!(failures, vec!["odd number", "error", "odd number"]);
    }

    #[test]
    fn test_filter_continue() {
        let items = vec![
            PipelineItem::new_success(1),
            PipelineItem::new_success(2),
            PipelineItem::new_failure("error"),
            PipelineItem::new_success(3),
        ];
        
        let (successes, failures): (Vec<_>, Vec<_>) = PipelineIterator::new(items.into_iter())
            .filter_continue(|&x| Ok(x % 2 == 0))
            .collect_results();
        
        assert_eq!(successes, vec![2]); // Only even number
        assert_eq!(failures, vec!["error"]); // Original error preserved
    }

    #[test]
    fn test_flat_map_continue() {
        let items = vec![
            PipelineItem::new_success(1),
            PipelineItem::new_success(2),
            PipelineItem::new_failure("error"),
        ];
        
        let (successes, failures): (Vec<_>, Vec<_>) = PipelineIterator::new(items.into_iter())
            .flat_map_continue(|x| vec![Ok(x), Ok(x * 10)])
            .collect_results();
        
        assert_eq!(successes, vec![1, 10, 2, 20]); // Flattened results
        assert_eq!(failures, vec!["error"]); // Original error preserved
    }

    #[test]
    fn test_pipeline_trait() {
        let data = vec![1, 2, 3];
        
        let (successes, failures): (Vec<_>, Vec<&str>) = data
            .into_iter()
            .pipeline::<&str>()
            .map_continue(|x| Ok(x * 2))
            .collect_results();
        
        assert_eq!(successes, vec![2, 4, 6]);
        assert_eq!(failures, Vec::<&str>::new());
    }
}