# Monadic Pipeline Design Document

## Executive Summary

This document outlines the strategic design for implementing a true monadic pipeline architecture for the Shadow encryption system. The current implementation uses functional-style processing but lacks genuine monadic composition. This design addresses that gap by introducing proper monadic combinators that enable fluent, chainable operations with comprehensive error handling and progress reporting.

## Current State Analysis

### What We Have (Phase 1 & 2 Completed)
- ✅ **Progress Reporting**: `ProgressStep` trait provides non-intrusive progress feedback
- ✅ **Functional Processing**: `ProcessContinue` trait separates successes from failures
- ✅ **Error Handling**: Comprehensive error types (`CoreError`, `FileError`, `CryptoError`, `ValidationError`)
- ✅ **Type Safety**: Strong typing with `EncryptionJob`, `EncryptionResult`, `EncryptionFailure`

### What We're Missing (True Monadic Composition)
```rust
// Current Implementation (Discrete Steps)
let paths = expand_patterns(patterns)?;
let regular_files = filter_regular_files(paths)?;
let classified_files = classify_files(regular_files)?;
let jobs = create_jobs(classified_files)?;

// Target Implementation (Monadic Chain)
let results = patterns
    .into_iter()
    .flat_map_continue(expand_patterns)
    .filter_continue(is_regular_file)
    .map_continue(classify_file)
    .map_continue(create_job)
    .collect_results();
```

## Monadic Architecture Design

### Core Monadic Types

#### 1. PipelineItem<T, E> - The Monadic Wrapper
```rust
/// Wrapper type that flows through the monadic pipeline
#[derive(Debug, Clone)]
pub enum PipelineItem<T, E> {
    Success(T),
    Failure(E),
}

impl<T, E> PipelineItem<T, E> {
    pub fn new_success(value: T) -> Self {
        Self::Success(value)
    }
    
    pub fn new_failure(error: E) -> Self {
        Self::Failure(error)
    }
    
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }
    
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failure(_))
    }
}
```

#### 2. PipelineIterator<T, E> - The Monadic Container
```rust
/// Iterator wrapper that provides monadic combinators
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
    pub fn new(iter: I) -> Self {
        Self { inner: iter }
    }
}
```

### Monadic Combinators

#### 1. flat_map_continue - Monadic Bind (>>=)
```rust
impl<I, T, E> PipelineIterator<I, T, E>
where
    I: Iterator<Item = PipelineItem<T, E>>,
{
    /// Monadic bind: transforms each success and flattens the results
    /// Failures flow through unchanged
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
}
```

#### 2. map_continue - Monadic Functor (fmap)
```rust
impl<I, T, E> PipelineIterator<I, T, E>
where
    I: Iterator<Item = PipelineItem<T, E>>,
{
    /// Monadic functor: transforms each success value
    /// Failures flow through unchanged
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
}
```

#### 3. filter_continue - Monadic Filter
```rust
impl<I, T, E> PipelineIterator<I, T, E>
where
    I: Iterator<Item = PipelineItem<T, E>>,
{
    /// Monadic filter: keeps only successes that match predicate
    /// Failed predicates become failures, existing failures flow through
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
```

#### 4. collect_results - Monadic Collection
```rust
impl<I, T, E> PipelineIterator<I, T, E>
where
    I: Iterator<Item = PipelineItem<T, E>>,
{
    /// Collect all results, separating successes from failures
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
}
```

### Progress Integration

#### Progress-Aware Combinators
```rust
impl<I, T, E> PipelineIterator<I, T, E>
where
    I: Iterator<Item = PipelineItem<T, E>>,
{
    /// Add progress reporting to any combinator
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
    
    /// Convenience method for standard progress reporting
    pub fn progress_step(self, name: &str) -> Self 
    where
        T: Clone,
        E: Clone,
    {
        self.with_progress(|item| {
            match item {
                PipelineItem::Success(_) => {
                    println!("✓ {}: Success", name);
                }
                PipelineItem::Failure(_) => {
                    println!("✗ {}: Failure", name);
                }
            }
        })
    }
}
```

## Implementation Strategy

### Phase 3: Monadic Foundation
1. **Create monadic types** (`PipelineItem`, `PipelineIterator`)
2. **Implement core combinators** (`map_continue`, `flat_map_continue`, `filter_continue`)
3. **Add collection methods** (`collect_results`, `collect_report`)

### Phase 4: Pipeline Conversion
1. **Convert pattern expansion** to use `flat_map_continue`
2. **Convert file filtering** to use `filter_continue`
3. **Convert job creation** to use `map_continue`
4. **Integrate progress reporting** throughout chain

### Phase 5: Advanced Combinators
1. **Implement `and_then_continue`** for dependent operations
2. **Add `parallel_map_continue`** for concurrent processing
3. **Create `batch_continue`** for grouped operations

## Target Pipeline Implementation

### Before (Current Discrete Steps)
```rust
pub fn encrypt_files(
    patterns: Vec<String>,
    options: EncryptionOptions,
    password: &str,
) -> CoreResult<EncryptionReport> {
    let password_hash = validate_password(password)?;
    let paths = expand_patterns(patterns)?;
    let regular_files = filter_regular_files(paths)?;
    let classified_files = classify_files(regular_files)?;
    let jobs = create_encryption_jobs(classified_files, &options)?;
    let (successes, failures) = process_batch_jobs(jobs, &password_hash, &options);
    
    Ok(EncryptionReport::new(successes, failures, total_duration))
}
```

### After (True Monadic Chain)
```rust
pub fn encrypt_files(
    patterns: Vec<String>,
    options: EncryptionOptions,
    password: &str,
) -> CoreResult<EncryptionReport> {
    let password_hash = validate_password(password)?;
    
    let (successes, failures) = patterns
        .into_iter()
        .map(|p| PipelineItem::new_success(p))
        .pipeline()
        .progress_step("Starting pattern processing")
        .flat_map_continue(|pattern| expand_pattern(&pattern))
        .progress_step("Pattern expansion complete")
        .filter_continue(|path| is_regular_file(path))
        .progress_step("File filtering complete")
        .map_continue(|path| classify_file(&path))
        .progress_step("File classification complete")
        .map_continue(|classified| create_encryption_job(classified, &options))
        .progress_step("Job creation complete")
        .map_continue(|job| process_encryption_job(job, &password_hash, &options))
        .progress_step("Encryption processing complete")
        .collect_results();
        
    let report = EncryptionReport::from_results(successes, failures);
    Ok(report)
}
```

## Error Handling Strategy

### Monadic Error Propagation
- **Successes flow forward** through the chain
- **Failures accumulate** without stopping the pipeline
- **Each step can produce new failures** while preserving existing ones
- **Final collection** separates all successes from all failures

### Error Context Preservation
```rust
#[derive(Debug, Clone)]
pub struct PipelineFailure {
    pub step: String,
    pub error: CoreError,
    pub context: HashMap<String, String>,
}

impl PipelineFailure {
    pub fn new(step: &str, error: CoreError) -> Self {
        Self {
            step: step.to_string(),
            error,
            context: HashMap::new(),
        }
    }
    
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}
```

## Benefits of Monadic Design

### 1. **Composability**
- Operations chain together naturally
- Easy to add/remove/reorder steps
- Clear data flow visualization

### 2. **Error Resilience**
- Individual failures don't halt entire pipeline
- Complete error collection and reporting
- Graceful degradation under partial failures

### 3. **Progress Transparency**
- Non-intrusive progress reporting
- Step-by-step visibility
- Easy debugging and monitoring

### 4. **Type Safety**
- Compile-time verification of pipeline structure
- Clear input/output types at each step
- Impossible to accidentally drop errors

### 5. **Testability**
- Each combinator is independently testable
- Easy to mock individual pipeline steps
- Clear separation of concerns

## Migration Path

### Backward Compatibility
- Existing discrete step functions remain unchanged
- New monadic interface wraps existing implementations
- Gradual migration allows incremental adoption

### Performance Considerations
- Iterator-based design enables lazy evaluation
- Memory efficient streaming of large file sets
- Parallel processing capabilities preserved

## Conclusion

This monadic design transforms the Shadow encryption pipeline from discrete error-prone steps into a fluent, resilient, and highly composable processing chain. The implementation maintains all existing functionality while adding true monadic composition, comprehensive error handling, and transparent progress reporting.

The resulting pipeline will be more maintainable, testable, and robust - continuing to process files even when individual operations fail, while providing complete visibility into both successes and failures.