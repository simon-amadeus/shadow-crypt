# Performance Specification

Detailed performance characteristics, optimization strategies, and benchmarking for the high-security file encryption system.

## Performance Targets

### Throughput Targets

**Encryption Performance:**
- Large files (>100MB): Target 500+ MB/s sustained throughput
- Medium files (1-100MB): Target 200+ MB/s average throughput  
- Small files (<1MB): Target 50+ files/second batch processing
- Directory encryption: Target 1000+ files/minute

**Decryption Performance:**
- Same targets as encryption (symmetric operations)
- Header parsing: <1ms per file regardless of size
- Partial file access: <10ms overhead for metadata extraction
- Streaming access: Enable random access without full decryption

**Memory Usage Targets:**
- Base memory footprint: <10MB for application
- Key derivation peak: 64MB (configurable up to 1GB)
- File processing: <32MB working memory regardless of file size
- Concurrent operations: Linear scaling with available memory

### Latency Targets

**Interactive Operations:**
- Password verification: 200ms (tunable via Argon2 parameters)
- File header parsing: <1ms
- Metadata extraction: <5ms
- Small file encryption: <10ms end-to-end

**Batch Operations:**
- Directory traversal: Parallel processing with configurable workers
- Bulk encryption: Pipeline optimization for sustained throughput
- Progress reporting: <100ms update intervals
- Cancellation response: <1 second from user request

## Algorithm Performance Characteristics

### AES-256-GCM Performance

**Hardware Accelerated (AES-NI):**
```rust
// Typical performance on modern x86_64 CPU with AES-NI
// Intel Core i7-12700K @ 3.6GHz baseline

pub struct AesGcmBenchmarks {
    pub encryption_throughput: f64,     // ~3.2 GB/s
    pub decryption_throughput: f64,     // ~3.4 GB/s  
    pub key_schedule_time: f64,         // ~50 nanoseconds
    pub gcm_setup_time: f64,            // ~100 nanoseconds
    pub authentication_overhead: f64,   // ~5% vs. AES-CTR
}
```

**Software Implementation:**
```rust
// Fallback performance without hardware acceleration
// Same CPU, software AES implementation

pub struct SoftwareAesBenchmarks {
    pub encryption_throughput: f64,     // ~150 MB/s
    pub decryption_throughput: f64,     // ~160 MB/s
    pub relative_overhead: f64,         // ~20x slower than hardware
    pub cpu_utilization: f64,           // ~95% of one core
}
```

### Argon2id Performance

**Parameter Impact Analysis:**
```rust
use std::time::Duration;

pub fn argon2_performance_analysis() -> Vec<ParameterSet> {
    vec![
        ParameterSet {
            name: "Fast (Development)",
            memory_mb: 8,
            iterations: 1,
            parallelism: 1,
            expected_time: Duration::from_millis(50),
            security_level: SecurityLevel::Development,
        },
        ParameterSet {
            name: "Balanced (Default)",
            memory_mb: 64,
            iterations: 3,
            parallelism: 4,
            expected_time: Duration::from_millis(200),
            security_level: SecurityLevel::Standard,
        },
        ParameterSet {
            name: "Secure (High Security)",
            memory_mb: 256,
            iterations: 5,
            parallelism: 8,
            expected_time: Duration::from_millis(800),
            security_level: SecurityLevel::High,
        },
        ParameterSet {
            name: "Paranoid (Maximum Security)",
            memory_mb: 1024,
            iterations: 10,
            parallelism: 16,
            expected_time: Duration::from_millis(3000),
            security_level: SecurityLevel::Maximum,
        },
    ]
}
```

### ChaCha20-Poly1305 Performance

**Software Optimization:**
```rust
// ChaCha20-Poly1305 performance characteristics
// Optimized for systems without AES hardware acceleration

pub struct ChaChaPolyBenchmarks {
    pub encryption_throughput: f64,     // ~1.8 GB/s (SIMD optimized)
    pub decryption_throughput: f64,     // ~1.9 GB/s
    pub cross_platform_consistency: bool, // true - same perf across platforms
    pub memory_usage: usize,            // ~16KB working memory
    pub simd_acceleration: bool,        // AVX2/NEON when available
}
```

## Optimization Strategies

### Hardware Acceleration

**CPU Feature Detection:**
```rust
use std::arch::is_x86_feature_detected;

pub fn detect_crypto_acceleration() -> CryptoCapabilities {
    let mut caps = CryptoCapabilities::default();
    
    if is_x86_feature_detected!("aes") {
        caps.aes_ni = true;
        caps.preferred_algorithm = AlgorithmId::AesGcm256;
    }
    
    if is_x86_feature_detected!("avx2") {
        caps.avx2 = true;
        caps.chacha_acceleration = true;
    }
    
    // ARM detection
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            caps.arm_crypto = true;
            caps.preferred_algorithm = AlgorithmId::AesGcm256;
        }
    }
    
    caps
}
```

**Algorithm Selection:**
```rust
pub fn select_optimal_algorithm(caps: &CryptoCapabilities) -> AlgorithmId {
    match caps {
        CryptoCapabilities { aes_ni: true, .. } => AlgorithmId::AesGcm256,
        CryptoCapabilities { arm_crypto: true, .. } => AlgorithmId::AesGcm256,
        CryptoCapabilities { avx2: true, .. } => AlgorithmId::ChaCha20Poly1305,
        _ => AlgorithmId::ChaCha20Poly1305, // Software fallback
    }
}
```

### Parallel Processing

**File-Level Parallelism:**
```rust
use rayon::prelude::*;

pub async fn encrypt_directory_parallel(
    dir: &Path,
    password: &str,
    worker_count: Option<usize>,
) -> Result<EncryptionStats> {
    let files = discover_files(dir).await?;
    let worker_count = worker_count.unwrap_or_else(num_cpus::get);
    
    // Configure thread pool for optimal performance
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .thread_name(|i| format!("crypto-worker-{}", i))
        .build()?;
        
    pool.install(|| {
        files.par_iter()
            .map(|file_path| encrypt_single_file(file_path, password))
            .collect::<Result<Vec<_>>>()
    })
}
```

**Streaming Optimization:**
```rust
pub struct StreamingEncryption {
    cipher: Aes256Gcm,
    buffer_size: usize,
    read_ahead: bool,
}

impl StreamingEncryption {
    pub fn new(key: &[u8]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            buffer_size: 64 * 1024, // 64KB chunks for optimal throughput
            read_ahead: true,
        }
    }
    
    pub async fn encrypt_stream<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<u64> 
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut total_bytes = 0u64;
        let mut buffer = vec![0u8; self.buffer_size];
        
        loop {
            let bytes_read = reader.read(&mut buffer).await?;
            if bytes_read == 0 { break; }
            
            let chunk = &buffer[..bytes_read];
            let encrypted = self.encrypt_chunk(chunk)?;
            
            writer.write_all(&encrypted).await?;
            total_bytes += bytes_read as u64;
        }
        
        Ok(total_bytes)
    }
}
```

### Memory Optimization

**Buffer Management:**
```rust
pub struct MemoryPool {
    buffers: Vec<Vec<u8>>,
    buffer_size: usize,
    max_buffers: usize,
}

impl MemoryPool {
    pub fn new(buffer_size: usize, max_buffers: usize) -> Self {
        Self {
            buffers: Vec::with_capacity(max_buffers),
            buffer_size,
            max_buffers,
        }
    }
    
    pub fn get_buffer(&mut self) -> Vec<u8> {
        self.buffers.pop()
            .unwrap_or_else(|| vec![0u8; self.buffer_size])
    }
    
    pub fn return_buffer(&mut self, mut buffer: Vec<u8>) {
        if self.buffers.len() < self.max_buffers {
            buffer.clear();
            buffer.resize(self.buffer_size, 0);
            self.buffers.push(buffer);
        }
        // Buffer dropped if pool is full - automatic cleanup
    }
}
```

**Zero-Copy Operations:**
```rust
use std::io::IoSlice;

pub fn encrypt_in_place(
    cipher: &Aes256Gcm,
    nonce: &Nonce,
    data: &mut [u8],
) -> Result<Vec<u8>> {
    // Encrypt directly in provided buffer when possible
    let tag = cipher.encrypt_in_place_detached(nonce, &[], data)?;
    Ok(tag.to_vec())
}

pub fn vectored_write(
    writer: &mut impl Write,
    header: &[u8],
    encrypted_data: &[u8],
    auth_tag: &[u8],
) -> Result<usize> {
    // Single system call for multiple buffers
    let bufs = &[
        IoSlice::new(header),
        IoSlice::new(encrypted_data),
        IoSlice::new(auth_tag),
    ];
    writer.write_vectored(bufs)
}
```

## Benchmarking Framework

### Performance Test Suite

**Microbenchmarks:**
```rust
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn benchmark_encryption_algorithms(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");
    
    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let data = vec![0u8; *size];
        
        group.bench_with_input(
            BenchmarkId::new("aes-256-gcm", size),
            size,
            |b, _| {
                b.iter(|| {
                    let cipher = Aes256Gcm::new(&random_key());
                    cipher.encrypt(&random_nonce(), data.as_slice())
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("chacha20-poly1305", size),
            size,
            |b, _| {
                b.iter(|| {
                    let cipher = ChaCha20Poly1305::new(&random_key());
                    cipher.encrypt(&random_nonce(), data.as_slice())
                })
            },
        );
    }
    
    group.finish();
}

fn benchmark_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");
    
    for (name, params) in [
        ("fast", (8 * 1024, 1, 1)),      // 8MB, 1 iter, 1 thread
        ("balanced", (64 * 1024, 3, 4)), // 64MB, 3 iter, 4 threads
        ("secure", (256 * 1024, 5, 8)),  // 256MB, 5 iter, 8 threads
    ].iter() {
        group.bench_with_input(
            BenchmarkId::new("argon2id", name),
            params,
            |b, (memory, time, parallel)| {
                b.iter(|| {
                    derive_key_with_params("test_password", &[0u8; 16], *memory, *time, *parallel)
                })
            },
        );
    }
    
    group.finish();
}

criterion_group!(benches, benchmark_encryption_algorithms, benchmark_key_derivation);
criterion_main!(benches);
```

**End-to-End Performance Tests:**
```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;
    
    #[test]
    fn test_large_file_performance() {
        let test_data = generate_test_data(100 * 1024 * 1024); // 100MB
        let password = "test_password_123";
        
        let start = Instant::now();
        let encrypted = encrypt_data(&test_data, password).unwrap();
        let encrypt_time = start.elapsed();
        
        let start = Instant::now();
        let decrypted = decrypt_data(&encrypted, password).unwrap();
        let decrypt_time = start.elapsed();
        
        assert_eq!(test_data, decrypted);
        
        let encrypt_throughput = test_data.len() as f64 / encrypt_time.as_secs_f64();
        let decrypt_throughput = test_data.len() as f64 / decrypt_time.as_secs_f64();
        
        println!("Encryption throughput: {:.1} MB/s", encrypt_throughput / 1_000_000.0);
        println!("Decryption throughput: {:.1} MB/s", decrypt_throughput / 1_000_000.0);
        
        // Assert performance targets
        assert!(encrypt_throughput > 100_000_000.0, "Encryption below 100 MB/s");
        assert!(decrypt_throughput > 100_000_000.0, "Decryption below 100 MB/s");
    }
    
    #[test]
    fn test_concurrent_file_processing() {
        let file_count = 1000;
        let file_size = 1024; // 1KB each
        let password = "test_password_123";
        
        let test_files: Vec<Vec<u8>> = (0..file_count)
            .map(|_| generate_test_data(file_size))
            .collect();
        
        let start = Instant::now();
        let encrypted_files: Vec<_> = test_files
            .par_iter()
            .map(|data| encrypt_data(data, password))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let total_time = start.elapsed();
        
        let files_per_second = file_count as f64 / total_time.as_secs_f64();
        println!("Concurrent processing: {:.1} files/second", files_per_second);
        
        assert!(files_per_second > 100.0, "Concurrent processing below 100 files/second");
    }
}
```

### Performance Monitoring

**Runtime Metrics:**
```rust
use std::sync::atomic::{AtomicU64, Ordering};

pub struct PerformanceMetrics {
    pub bytes_encrypted: AtomicU64,
    pub bytes_decrypted: AtomicU64,
    pub files_processed: AtomicU64,
    pub encryption_time: AtomicU64,
    pub decryption_time: AtomicU64,
    pub key_derivation_time: AtomicU64,
}

impl PerformanceMetrics {
    pub fn record_encryption(&self, bytes: u64, duration: Duration) {
        self.bytes_encrypted.fetch_add(bytes, Ordering::Relaxed);
        self.encryption_time.fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
        self.files_processed.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn get_throughput_mbps(&self) -> f64 {
        let total_bytes = self.bytes_encrypted.load(Ordering::Relaxed) +
                         self.bytes_decrypted.load(Ordering::Relaxed);
        let total_time_ns = self.encryption_time.load(Ordering::Relaxed) +
                           self.decryption_time.load(Ordering::Relaxed);
        
        if total_time_ns == 0 { return 0.0; }
        
        let total_time_s = total_time_ns as f64 / 1_000_000_000.0;
        let throughput_bps = total_bytes as f64 / total_time_s;
        throughput_bps / 1_000_000.0 // Convert to MB/s
    }
}
```

**Profiling Integration:**
```rust
#[cfg(feature = "profiling")]
use pprof::ProfilerGuard;

pub struct ProfilingSession {
    #[cfg(feature = "profiling")]
    guard: ProfilerGuard<'static>,
}

impl ProfilingSession {
    pub fn start() -> Self {
        #[cfg(feature = "profiling")]
        let guard = pprof::ProfilerGuard::new(100).unwrap();
        
        Self {
            #[cfg(feature = "profiling")]
            guard,
        }
    }
    
    pub fn finish(self, output_path: &Path) -> Result<()> {
        #[cfg(feature = "profiling")]
        {
            if let Ok(report) = self.guard.report().build() {
                let file = std::fs::File::create(output_path)?;
                report.flamegraph(file)?;
            }
        }
        Ok(())
    }
}
```

## Platform-Specific Optimizations

### x86_64 Optimizations

**AES-NI Utilization:**
```rust
#[cfg(target_arch = "x86_64")]
mod x86_optimizations {
    use std::arch::x86_64::*;
    
    pub fn optimized_aes_encrypt(
        key_schedule: &[__m128i; 15],
        data: &mut [u8],
    ) {
        unsafe {
            for chunk in data.chunks_exact_mut(16) {
                let mut block = _mm_loadu_si128(chunk.as_ptr() as *const __m128i);
                
                // AES encryption rounds using intrinsics
                block = _mm_xor_si128(block, key_schedule[0]);
                for i in 1..14 {
                    block = _mm_aesenc_si128(block, key_schedule[i]);
                }
                block = _mm_aesenclast_si128(block, key_schedule[14]);
                
                _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, block);
            }
        }
    }
}
```

### ARM64 Optimizations

**ARM Crypto Extensions:**
```rust
#[cfg(target_arch = "aarch64")]
mod arm_optimizations {
    use std::arch::aarch64::*;
    
    pub fn optimized_aes_encrypt_arm(
        round_keys: &[uint8x16_t; 15],
        data: &mut [u8],
    ) {
        unsafe {
            for chunk in data.chunks_exact_mut(16) {
                let mut block = vld1q_u8(chunk.as_ptr());
                
                // ARM AES encryption
                block = veorq_u8(block, round_keys[0]);
                for i in 1..14 {
                    block = vaesmcq_u8(vaeseq_u8(block, round_keys[i]));
                }
                block = vaeseq_u8(block, round_keys[14]);
                
                vst1q_u8(chunk.as_mut_ptr(), block);
            }
        }
    }
}
```

### Memory Management Optimizations

**Platform-Specific Memory Locking:**
```rust
#[cfg(unix)]
mod unix_memory {
    use libc::{mlock, munlock, sysconf, _SC_PAGESIZE};
    
    pub fn lock_memory(data: &mut [u8]) -> Result<()> {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        let start = data.as_ptr() as usize;
        let aligned_start = start & !(page_size - 1);
        let aligned_len = ((start + data.len() + page_size - 1) & !(page_size - 1)) - aligned_start;
        
        let result = unsafe { mlock(aligned_start as *const libc::c_void, aligned_len) };
        if result == 0 { Ok(()) } else { Err(io::Error::last_os_error().into()) }
    }
}

#[cfg(windows)]
mod windows_memory {
    use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};
    
    pub fn lock_memory(data: &mut [u8]) -> Result<()> {
        let result = unsafe {
            VirtualLock(data.as_mut_ptr() as *mut _, data.len())
        };
        if result != 0 { Ok(()) } else { Err(io::Error::last_os_error().into()) }
    }
}
```

## Performance vs. Security Trade-offs

### Configurable Security Levels

```rust
#[derive(Debug, Clone, Copy)]
pub enum SecurityProfile {
    Fast {
        argon2_memory_mb: u32,    // 8MB
        argon2_iterations: u32,   // 1
        padding_level: PaddingLevel, // Minimal
    },
    Balanced {
        argon2_memory_mb: u32,    // 64MB
        argon2_iterations: u32,   // 3
        padding_level: PaddingLevel, // Standard
    },
    Secure {
        argon2_memory_mb: u32,    // 256MB
        argon2_iterations: u32,   // 5
        padding_level: PaddingLevel, // Maximum
    },
}

#[derive(Debug, Clone, Copy)]
pub enum PaddingLevel {
    None,       // No padding - fastest, reveals size patterns
    Minimal,    // Round to nearest 1KB
    Standard,   // Round to nearest 16KB 
    Maximum,    // Round to nearest 1MB
}
```

### Adaptive Performance

**Dynamic Parameter Adjustment:**
```rust
pub struct AdaptiveConfig {
    target_latency: Duration,
    current_performance: f64,
    adjustment_factor: f64,
}

impl AdaptiveConfig {
    pub fn adjust_parameters(&mut self, measured_time: Duration) -> SecurityProfile {
        let latency_ratio = measured_time.as_secs_f64() / self.target_latency.as_secs_f64();
        
        if latency_ratio > 1.5 {
            // Too slow - reduce security parameters
            self.adjustment_factor *= 0.9;
        } else if latency_ratio < 0.5 {
            // Too fast - can increase security
            self.adjustment_factor *= 1.1;
        }
        
        self.compute_profile()
    }
}
```

See [cryptography.md](cryptography.md) for algorithm details and [security.md](security.md) for security vs. performance considerations.