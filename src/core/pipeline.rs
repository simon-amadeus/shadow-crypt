//! Pipeline composition utilities for functional programming.

use crate::core::types::{CoreResult, Metrics};
use std::time::Instant;

/// A pipeline step that transforms input to output.
pub trait PipelineStep<Input, Output> {
    fn execute(&self, input: Input) -> CoreResult<Output>;
}

/// Pipeline builder for composing transformation steps.
pub struct Pipeline<T> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Pipeline<T> {
    pub fn start() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Functional pipeline utilities and combinators.
pub struct PipelineOps;

impl PipelineOps {
    /// Apply a function to each item in a collection, collecting results.
    pub fn map_collect<T, U, E, F>(items: Vec<T>, f: F) -> Result<Vec<U>, E>
    where
        F: Fn(T) -> Result<U, E>,
    {
        items.into_iter().map(f).collect()
    }
    
    /// Filter and transform items, keeping only successful transformations.
    pub fn filter_map_collect<T, U, E, F>(items: Vec<T>, f: F) -> Result<Vec<U>, E>
    where
        F: Fn(T) -> Result<Option<U>, E>,
    {
        let mut results = Vec::new();
        for item in items {
            match f(item)? {
                Some(result) => results.push(result),
                None => continue,
            }
        }
        Ok(results)
    }
    
    /// Partition results into successes and failures.
    pub fn partition_results<T, E>(results: Vec<Result<T, E>>) -> (Vec<T>, Vec<E>) {
        let mut successes = Vec::new();
        let mut failures = Vec::new();
        
        for result in results {
            match result {
                Ok(success) => successes.push(success),
                Err(failure) => failures.push(failure),
            }
        }
        
        (successes, failures)
    }
    
    /// Time the execution of a function and return result with metrics.
    pub fn timed<T, E, F>(f: F) -> Result<(T, Metrics), E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let start = Instant::now();
        let result = f()?;
        let duration = start.elapsed();
        
        let metrics = Metrics::new().with_duration(duration);
        Ok((result, metrics))
    }
    
    /// Apply a side effect function without changing the value.
    pub fn tap<T, F>(value: T, f: F) -> T
    where
        F: FnOnce(&T),
    {
        f(&value);
        value
    }
}

/// Macro for creating pipeline-style function composition.
#[macro_export]
macro_rules! pipeline {
    ($input:expr) => {
        $input
    };
    ($input:expr => $first:expr) => {
        $first($input)
    };
    ($input:expr => $first:expr => $($rest:expr)=>+) => {
        pipeline!($first($input)? => $($rest)=>+)
    };
}

/// Monadic bind operator for Result types.
pub trait ResultExt<T, E> {
    fn and_then_tap<F>(self, f: F) -> Result<T, E>
    where
        F: FnOnce(&T);
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn and_then_tap<F>(self, f: F) -> Result<T, E>
    where
        F: FnOnce(&T),
    {
        match self {
            Ok(value) => {
                f(&value);
                Ok(value)
            }
            Err(e) => Err(e),
        }
    }
}