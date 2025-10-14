# Domain Structure Proposal

## Current Structure (Layer-based)
```
domain/
├── shared/           # Entities (good!)
├── services/         # All services mixed together
├── repositories/     # Technical layer
└── errors.rs
```

## Proposed Structure (Capability-based)
```
domain/
├── shared/           # Keep as-is - shared entities & value objects
├── encryption/       # Everything related to encrypting files
├── decryption/       # Everything related to decrypting files  
├── listing/          # Everything related to listing/inspecting files
├── file_operations/  # Core file I/O with atomic transactions
└── errors.rs
```

## Vertical Slice Benefits

Each slice contains:
- **Domain Service** (business logic)
- **Repository Interface** (if needed)
- **Domain Events** (if needed)
- **Value Objects** (slice-specific)

## Detailed Structure

```rust
domain/
├── shared/
│   ├── entities/         # Core entities used across slices
│   ├── value_objects/    # Algorithm, Paths, etc.
│   └── common/           # Common types, errors
│
├── encryption/
│   ├── service.rs        # EncryptionService trait + logic
│   ├── options.rs        # EncryptionOptions, EncryptionResult
│   └── mod.rs
│
├── decryption/
│   ├── service.rs        # DecryptionService trait + logic  
│   ├── options.rs        # DecryptionOptions, DecryptionResult
│   └── mod.rs
│
├── listing/
│   ├── service.rs        # ListingService trait + logic
│   ├── file_info.rs      # FileInfo, DirectoryListing
│   └── mod.rs
│
├── file_operations/
│   ├── handler.rs        # FileHandler trait (atomic operations)
│   ├── transactions.rs   # Transaction types & builder
│   └── mod.rs
│
└── mod.rs               # Clean re-exports by capability
```