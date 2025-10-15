# Monadic Pipeline Design Document

## Overview

This document outlines the design for transforming the current encryption pipeline into a monadic functional pipeline that provides resilient error handling, progress reporting, and continues processing even when individual files fail.

## Current Architecture

The existing pipeline follows a simple sequential approach:
```rust
patterns -> expand_patterns -> filter_regular_files -> classify_files -> validate -> create_jobs -> encrypt_batch -> report
```

**Issues with Current Approach:**
- **Early Termination**: Any failure stops the entire pipeline
- **No Progress Feedback**: Users don't see what's happening during long operations
- **Binary Success/Failure**: Either everything works or nothing works
- **Poor Error Aggregation**: Individual file failures aren't collected and reported comprehensively

## Target Architecture: Monadic Pipeline

The new architecture will implement four key changes to provide resilient, user-friendly processing:

## 1. Progress Wrapper

### Purpose
Provide real-time feedback to users during long-running operations without cluttering business logic.

### Design
```rust
/// Wrapper that adds progress reporting to any iterator
pub struct ProgressWrapper<I> {
    inner: I,
    message: String,
}

impl<I: Iterator> Iterator for ProgressWrapper<I> {
    type Item = I::Item;
    
    fn next(&mut self) -> Option<Self::Item> {
        // Show progress indicator on first call
        // Delegate to inner iterator
        self.inner.next()
    }
}

/// Extension trait to add progress reporting to any iterator
pub trait MonadicPipeline<T>: Iterator<Item = T> + Sized {
    fn progress_step(self, message: &str) -> ProgressWrapper<Self> {
        println!("⏳ {}", message);
        ProgressWrapper { inner: self, message: message.to_string() }
    }
}
```

### Usage Example
```rust
let results = patterns
    .into_iter()
    .progress_step("📁 Expanding file patterns...")
    .flat_map(|pattern| expand_pattern(pattern))
    .progress_step("🔍 Filtering regular files...")
    .filter(|path| is_regular_file(path))
    .collect();
```

### Benefits
- **Non-intrusive**: Business logic remains clean
- **Chainable**: Fits naturally into functional pipelines
- **User Experience**: Real-time feedback during operations
- **Minimal Overhead**: Zero cost when not used

## 2. Critical vs Non-Critical Boundaries

### Purpose
Distinguish between failures that should stop everything (critical) versus failures that should be collected and reported (non-critical).

### Design Philosophy

**Critical Failures (Fail Fast):**
- Password validation failure
- Invalid encryption options
- Unable to create crypto session
- System-level issues (permissions, disk space)

**Non-Critical Failures (Continue Processing):**
- Individual file access errors
- Individual file encryption failures
- Non-fatal I/O issues

### Implementation Strategy
```rust
pub fn execute(patterns: Vec<String>, password: String, options: EncryptionOptions) -> CoreResult<EncryptionReport> {
    // CRITICAL BOUNDARY: These must succeed or abort entirely
    validate_password(&password)?;           // Critical: Invalid password = abort
    validate_options(&options)?;             // Critical: Invalid options = abort  
    let session = create_session(&password, options.algorithm)?; // Critical: Crypto failure = abort
    
    // NON-CRITICAL BOUNDARY: Collect failures, continue processing
    let results = patterns
        .into_iter()
        .flat_map_continue(|pattern| expand_pattern(pattern))     // Continue on pattern errors
        .filter_continue(|path| is_regular_file(path))            // Continue on access errors
        .map_continue(|path| create_encryption_job(path))         // Continue on job creation errors
        .map_continue(|job| encrypt_file(job, &session))          // Continue on encryption errors
        .collect_results(); // Collect both successes and failures
    
    // Generate comprehensive report
    Ok(EncryptionReport::from_results(results))
}
```

### Error Boundary Rules
1. **Before Session Creation**: All errors are critical (fail fast)
2. **After Session Creation**: File-level errors are non-critical (continue processing)
3. **System-Level Issues**: Always critical regardless of pipeline stage

## 3. Result Collection

### Purpose
Collect both successful operations and failures for comprehensive reporting at the end.

### Design
```rust
/// Result of a pipeline operation that can be either success or failure
#[derive(Debug)]
pub struct PipelineItem<T, E> {
    pub result: Result<T, E>,
}

impl<T, E> PipelineItem<T, E> {
    pub fn success(value: T) -> Self {
        Self { result: Ok(value) }
    }
    
    pub fn failure(error: E) -> Self {
        Self { result: Err(error) }
    }
    
    pub fn is_success(&self) -> bool {
        self.result.is_ok()
    }
}

/// Enhanced outcome type for final reporting
#[derive(Debug, Clone)]
pub enum EncryptionOutcome {
    Success(EncryptionResult),
    Failure(EncryptionFailure),
}

/// Enhanced report with detailed success/failure breakdown
#[derive(Debug)]
pub struct EncryptionReport {
    pub outcomes: Vec<EncryptionOutcome>,
    pub total_files: usize,
    pub successful: usize,
    pub failed: usize,
    pub total_duration: Duration,
    pub total_input_size: u64,
    pub total_output_size: u64,
}
```

### Benefits
- **Complete Visibility**: Users see exactly what happened to each file
- **No Lost Work**: Successful encryptions aren't lost due to later failures
- **Detailed Reporting**: Rich information for troubleshooting
- **Resumable Operations**: Failed files can be identified and retried

## 4. Pipeline Combinators

### Purpose
Provide functional combinators that continue processing on failure while collecting results.

### Core Combinators

#### `map_continue`
Transforms items while collecting failures:
```rust
fn map_continue<U, E, F>(self, f: F) -> ContinueMapper<Self, F, U, E>
where
    F: Fn(T) -> Result<U, E>,
{
    ContinueMapper { inner: self, mapper: f, _phantom: PhantomData }
}

impl<I, F, T, U, E> Iterator for ContinueMapper<I, F, U, E>
where
    I: Iterator<Item = T>,
    F: Fn(T) -> Result<U, E>,
{
    type Item = PipelineItem<U, E>;
    
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|item| match (self.mapper)(item) {
            Ok(value) => PipelineItem::success(value),
            Err(error) => PipelineItem::failure(error),
        })
    }
}
```

#### `flat_map_continue`
Expands items while collecting failures:
```rust
fn flat_map_continue<U, E, F, I>(self, f: F) -> ContinueFlatMapper<Self, F, U, E>
where
    F: Fn(T) -> Result<I, E>,
    I: IntoIterator<Item = U>,
```

#### `filter_continue`
Filters items while collecting predicate failures:
```rust
fn filter_continue<E, F>(self, predicate: F) -> ContinueFilter<Self, F, E>
where
    F: Fn(&T) -> Result<bool, E>,
```

#### `collect_results`
Collects all pipeline items into a vector:
```rust
fn collect_results<U, E>(self) -> Vec<PipelineItem<U, E>>
where
    Self: Iterator<Item = PipelineItem<U, E>>,
{
    self.collect()
}
```

### Usage Pattern
```rust
let results: Vec<PipelineItem<EncryptedData, CoreError>> = patterns
    .into_iter()
    .progress_step("📁 Expanding file patterns...")
    .flat_map_continue(|pattern| expand_patterns(&pattern))
    .progress_step("🔍 Filtering regular files...")
    .filter_continue(|path| is_regular_file(path))
    .progress_step("⚙️ Creating encryption jobs...")
    .map_continue(|path| create_encryption_job(path))
    .progress_step("🔐 Encrypting files...")
    .map_continue(|job| encrypt_file(job, &session))
    .collect_results();
```

## Implementation Strategy

### Phase 1: Foundation
1. Create the `PipelineItem<T, E>` type
2. Implement the `MonadicPipeline` trait with `progress_step`
3. Add basic combinator infrastructure

### Phase 2: Core Combinators
1. Implement `map_continue` combinator
2. Implement `flat_map_continue` combinator
3. Implement `filter_continue` combinator
4. Add `collect_results` method

### Phase 3: Pipeline Integration
1. Identify critical vs non-critical boundaries in existing pipeline
2. Replace existing pipeline with monadic version
3. Update result types to use `EncryptionOutcome`
4. Enhance `EncryptionReport` with detailed statistics

### Phase 4: Testing & Refinement
1. Test with various failure scenarios
2. Verify progress reporting works correctly
3. Ensure comprehensive error collection
4. Performance validation

## Expected Benefits

### User Experience
- **Real-time Feedback**: Users see progress during long operations
- **Comprehensive Results**: Complete report of what succeeded/failed
- **Fault Tolerance**: Individual file failures don't stop the entire operation
- **Resumability**: Failed files can be identified and retried

### Developer Experience
- **Composable**: Pipeline stages can be easily added/removed/reordered
- **Testable**: Each combinator can be tested independently
- **Readable**: Functional pipeline clearly shows data flow
- **Maintainable**: Clear separation of concerns between stages

### Operational Benefits
- **Robustness**: System continues working even with partial failures
- **Observability**: Clear insight into what's happening during operations
- **Efficiency**: No wasted work when individual files fail
- **Scalability**: Pattern works well for batch operations on many files

## Conclusion

This monadic pipeline design provides a robust foundation for resilient file processing operations. By implementing these four key changes, we achieve a system that is both user-friendly and operationally robust, while maintaining clean functional composition patterns.

The design prioritizes:
1. **Resilience**: Continue processing despite individual failures
2. **Transparency**: Clear progress reporting and comprehensive results
3. **Composability**: Functional pipeline that's easy to extend and modify
4. **Maintainability**: Clean separation between business logic and cross-cutting concerns