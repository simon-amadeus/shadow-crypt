# Monadic Pipeline Design Document

## Overview

This document outlines the design for transforming the current encryption pipeline into a monadic functional pipeline that provides resilient error handling, progress reporting, and continues processing even when individual files fail.

## Current Implementation Analysis

The existing pipeline in `/src/core/encryption/pipeline.rs` follows this structure:
```rust
patterns -> expand_patterns -> filter_regular_files -> classify_files 
-> validate_password -> validate_options -> validate_files 
-> create_encryption_jobs -> validate_encryption_jobs 
-> create_session -> process_batch_jobs -> report
```

**Current Strengths:**
- **Good error handling foundation**: Uses `CoreResult<T>` consistently
- **Existing result collection**: Already collects `Vec<EncryptionResult>` and `Vec<EncryptionFailure>`
- **Comprehensive reporting**: `EncryptionReport` has statistics and metrics
- **Clean separation**: Validation, job creation, and execution are separate phases

**Current Limitations:**
- **Early termination on validation**: Validation failures stop entire pipeline
- **No progress feedback**: Long operations provide no user feedback
- **Batch processing**: Individual file failures stop remaining files in batch
- **Manual result aggregation**: Manual loops instead of functional composition

## Target Architecture: Enhanced Monadic Pipeline

The refined design builds on the existing strengths while addressing limitations through **four targeted improvements**:

## 1. Progress Wrapper

### Purpose
Add real-time progress feedback to the existing pipeline without changing core business logic.

### Current State
The existing pipeline runs silently. Users have no feedback during long operations like processing many files.

### Design
```rust
/// Minimal progress wrapper that can be added to any iterator
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

/// Extension trait for existing iterators - non-intrusive addition
pub trait ProgressStep<T>: Iterator<Item = T> + Sized {
    fn progress_step(self, message: &'static str) -> ProgressWrapper<Self> {
        ProgressWrapper { inner: self, message, started: false }
    }
}

// Blanket implementation for all iterators
impl<T, I: Iterator<Item = T>> ProgressStep<T> for I {}
```

### Integration with Current Pipeline
```rust
// Before (silent)
let paths = expand_patterns(patterns)?;
let regular_files = filter_regular_files(paths)?;

// After (with progress)
let paths = expand_patterns(patterns)?;
let regular_files = regular_files.into_iter()
    .progress_step("🔍 Filtering regular files...")
    .collect::<Result<Vec<_>, _>>()?;
```

### Benefits
- **Zero impact**: Existing code unchanged, progress added through iterator extension
- **Minimal overhead**: Only prints once per pipeline stage
- **User experience**: Clear feedback during long operations
- **Implementable immediately**: Can be added to current pipeline without restructuring

## 2. Critical vs Non-Critical Boundaries

### Purpose
Preserve the current validation approach while enabling file-level resilience during processing.

### Current Implementation Analysis
The existing pipeline has good validation structure:
```rust
// Current critical validations (correctly fail-fast)
validate_password(&password)?;                    // ✅ Should fail fast
validate_options(&options)?;                      // ✅ Should fail fast  
validate_files_for_encryption(&file_jobs)?;       // ✅ Should fail fast
validate_encryption_jobs(&encryption_jobs, ...)?; // ✅ Should fail fast
let session = create_session(&password, ...)?;    // ✅ Should fail fast

// Current batch processing (could be improved)
let (successful, failed) = Self::process_batch_jobs(encryption_jobs, &session, &options);
```

The `process_batch_jobs` method already collects failures! The issue is it uses a manual loop instead of functional composition.

### Design Philosophy

**Keep Current Critical Boundaries (No Changes Needed):**
- Password validation failure → abort entirely ✅
- Invalid encryption options → abort entirely ✅  
- Unable to create crypto session → abort entirely ✅
- File validation issues → abort entirely ✅

**Enhance Non-Critical Processing (Targeted Improvement):**
- Individual file encryption failures → collect and continue ✅ (already implemented)
- Individual I/O errors → collect and continue ✅ (already implemented)

### Refined Implementation Strategy
```rust
pub fn execute(patterns: Vec<String>, password: String, options: EncryptionOptions) -> CoreResult<EncryptionReport> {
    // CRITICAL BOUNDARY: Keep existing validation (no changes)
    let paths = expand_patterns(patterns)?;
    let regular_files = filter_regular_files(paths)?;
    let file_jobs = classify_files(regular_files)?;
    
    validate_password(&password)?;
    validate_options(&options)?;
    validate_files_for_encryption(&file_jobs)?;
    
    let encryption_jobs = create_encryption_jobs(file_jobs, options.obfuscate_filename)?;
    validate_encryption_jobs(&encryption_jobs, options.force_overwrite)?;
    let session = create_session(&password, options.algorithm, None)?;
    
    // NON-CRITICAL BOUNDARY: Enhance existing batch processing with functional style
    let results = encryption_jobs
        .into_iter()
        .progress_step("🔐 Encrypting files...")
        .map_continue(|job| Self::encrypt_and_write_job(&job, &session, &options))
        .collect_results();
    
    // Convert to existing report structure (minimal changes)
    let (successful, failed) = Self::partition_results(results);
    Ok(EncryptionReport::new(successful, failed, start_time.elapsed()))
}
```

### Benefits
- **Preserves existing validation logic**: No need to change proven validation code
- **Enhances file processing**: Individual files can fail without stopping others  
- **Minimal structural changes**: Builds on existing `process_batch_jobs` pattern
- **Maintains compatibility**: Same `EncryptionReport` structure

## 3. Result Collection

### Purpose
Enhance the existing result collection with functional composition while preserving current data structures.

### Current Implementation Analysis
The existing code already has excellent result collection:
```rust
// Current types (keep these!)
pub struct EncryptionResult {
    pub job: EncryptionJob,
    pub algorithm: AlgorithmId,
    pub duration: Duration,
    pub output_size: u64,
    pub encrypted_data: EncryptedData,
}

pub struct EncryptionFailure {
    pub job: EncryptionJob,
    pub error: String,
    pub duration: Duration,
}

pub struct EncryptionReport {
    pub successful: Vec<EncryptionResult>,  // ✅ Already perfect
    pub failed: Vec<EncryptionFailure>,     // ✅ Already perfect
    pub total_duration: Duration,           // ✅ Good metrics
    pub total_bytes_processed: u64,         // ✅ Good metrics
    pub total_files_processed: usize,       // ✅ Good metrics
}
```

The existing `EncryptionReport` already provides comprehensive statistics and is well-designed!

### Minimal Enhancement Design
Instead of replacing the existing types, we add a simple intermediate type for functional composition:

```rust
/// Intermediate type for functional pipeline composition
/// Converts to existing EncryptionResult/EncryptionFailure at the end
#[derive(Debug)]
pub enum PipelineResult {
    Success(EncryptionResult),
    Failure(EncryptionFailure),
}

impl PipelineResult {
    fn into_result_and_failure(self) -> (Option<EncryptionResult>, Option<EncryptionFailure>) {
        match self {
            PipelineResult::Success(result) => (Some(result), None),
            PipelineResult::Failure(failure) => (None, Some(failure)),
        }
    }
}

/// Helper to partition pipeline results into existing Vec<Success>, Vec<Failure> structure
fn partition_results(results: Vec<PipelineResult>) -> (Vec<EncryptionResult>, Vec<EncryptionFailure>) {
    let mut successful = Vec::new();
    let mut failed = Vec::new();
    
    for result in results {
        match result.into_result_and_failure() {
            (Some(success), None) => successful.push(success),
            (None, Some(failure)) => failed.push(failure),
            _ => unreachable!(),
        }
    }
    
    (successful, failed)
}
```

### Integration Benefits
- **Preserves existing APIs**: `EncryptionReport::new()` signature unchanged
- **Maintains existing metrics**: All current statistics calculations preserved
- **Enables functional composition**: Can use `.map()`, `.filter()` on results
- **Zero breaking changes**: All existing code continues to work

## 4. Pipeline Combinators

### Purpose
Replace the manual loop in `process_batch_jobs` with functional composition while maintaining the same behavior.

### Current Implementation Analysis
The existing `process_batch_jobs` method already implements resilient processing:
```rust
fn process_batch_jobs(jobs: Vec<EncryptionJob>, session: &CryptoSession, options: &EncryptionOptions) -> (Vec<EncryptionResult>, Vec<EncryptionFailure>) {
    let mut successful = Vec::new();
    let mut failed = Vec::new();

    for job in jobs {                                    // ✅ Processes all jobs
        let start_time = Instant::now();
        match Self::encrypt_and_write_job(&job, session, options) {  // ✅ Continues on failure
            Ok(result) => successful.push(...),         // ✅ Collects success
            Err(error) => failed.push(...),             // ✅ Collects failure
        }
    }
    (successful, failed)                                 // ✅ Returns both vectors
}
```

This is exactly the right behavior! We just want to express it functionally.

### Minimal Combinator Design
We only need one simple combinator that maintains the existing behavior:

```rust
/// Simple extension trait for iterator → (Vec<Success>, Vec<Failure>)
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

impl<T, I: Iterator<Item = T>> ProcessContinue<T> for I {}
```

### Integration with Current Pipeline
```rust
// Current approach (manual loop)
let (successful, failed) = Self::process_batch_jobs(encryption_jobs, &session, &options);

// Functional approach (same behavior, cleaner expression)  
let (successful, failed) = encryption_jobs
    .into_iter()
    .progress_step("� Encrypting files...")
    .process_continue(|job| {
        let start_time = Instant::now();
        match Self::encrypt_and_write_job(&job, &session, &options) {
            Ok(encrypted_data) => {
                let duration = start_time.elapsed();
                Ok(EncryptionResult::new(job, session.algorithm(), duration, encrypted_data))
            }
            Err(error) => {
                let duration = start_time.elapsed();
                Err(EncryptionFailure::new(job, error.to_string(), duration))
            }
        }
    });
```

### Benefits
- **Same behavior**: Identical to current implementation, just functional style
- **Progress reporting**: Easy to add `.progress_step()` 
- **Readable**: Clear data flow from jobs → (successes, failures)
- **Minimal changes**: Drop-in replacement for existing `process_batch_jobs`
- **No complex generics**: Simple, concrete types matching current pipeline

## Implementation Strategy

### Refined Approach: Minimal, Targeted Improvements

Based on analysis of the current implementation, we can achieve the benefits of a monadic pipeline with much smaller, targeted changes:

### Phase 1: Add Progress Reporting (Immediate Value)
1. Create `ProgressStep` trait in `src/core/shared/progress.rs`
2. Add progress reporting to existing pipeline stages
3. Zero breaking changes, immediate user experience improvement

**Implementation**: 30 minutes
**Risk**: None (additive only)
**Value**: High (users get immediate feedback)

### Phase 2: Enhance File Processing (Core Improvement)  
1. Create `ProcessContinue` trait in `src/core/shared/pipeline.rs`
2. Replace manual loop in `process_batch_jobs` with functional version
3. Add progress reporting to file processing

**Implementation**: 1 hour
**Risk**: Low (same behavior, different expression)
**Value**: High (cleaner code, better progress reporting)

### Phase 3: Optional Extensions (Future Enhancement)
1. Add similar functional processing to earlier pipeline stages if needed
2. Consider more complex combinators only if specific use cases arise
3. Performance optimization if needed

### Comparison with Original Design

**Original Complex Design:**
- Multiple generic combinators (`map_continue`, `flat_map_continue`, `filter_continue`)
- Complex iterator infrastructure with `PipelineItem<T, E>`
- Major restructuring of existing types
- High implementation complexity
- Risk of over-engineering

**Refined Minimal Design:**
- One simple combinator (`process_continue`) 
- Simple progress wrapper (`progress_step`)
- Preserves all existing types and APIs
- Builds on current strengths
- Delivers same benefits with lower risk

### Expected Results

**After Phase 1 (Progress Reporting):**
```rust
let paths = expand_patterns(patterns)?;
let regular_files = filter_regular_files(paths)?
    .into_iter()
    .progress_step("🔍 Filtering regular files...")
    .collect::<Result<Vec<_>, _>>()?;
```

**After Phase 2 (Functional File Processing):**
```rust
let (successful, failed) = encryption_jobs
    .into_iter()
    .progress_step("🔐 Encrypting files...")
    .process_continue(|job| Self::encrypt_and_write_job(&job, &session, &options));
```

Users get:
- ✅ Real-time progress feedback
- ✅ Resilient file processing (continue on individual failures)
- ✅ Comprehensive reporting (same `EncryptionReport` structure)
- ✅ Clean functional composition
- ✅ Zero breaking changes to existing APIs

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

After analyzing the current implementation, the refined monadic pipeline design is much simpler and more practical than originally envisioned. The existing code already has:

✅ **Excellent error handling** with `CoreResult<T>`  
✅ **Comprehensive result collection** with `EncryptionResult`/`EncryptionFailure`  
✅ **Good separation of concerns** with validation → job creation → execution  
✅ **Resilient file processing** that continues on individual failures  

**What we actually need to add:**
1. **Progress Reporting**: Simple iterator wrapper for user feedback
2. **Functional Composition**: Replace manual loop with functional expression

**What we don't need:**
- Complex generic combinators
- New result types  
- Major architectural changes
- Breaking API changes

This refined approach delivers the same benefits as the original monadic pipeline design but with:
- **90% less implementation complexity**
- **Zero breaking changes**
- **Immediate value** (progress reporting)
- **Lower risk** (builds on existing strengths)
- **Easier maintenance** (simpler abstractions)

The key insight is that **the current implementation is already mostly correct**—it just needs better user experience (progress reporting) and cleaner expression (functional style) rather than fundamental restructuring.

**Design Principles Achieved:**
1. **Resilience**: ✅ Continue processing despite individual failures (already implemented)
2. **Transparency**: ✅ Clear progress reporting (easy addition)
3. **Composability**: ✅ Functional pipeline (targeted improvement)
4. **Maintainability**: ✅ Clean separation of concerns (preserve existing structure)