//! Integration tests for the new versioning architecture
//! 
//! Tests the complete versioning system including detection, dispatch, and migration planning.

use shadow_crypt::shared::versioning::{HeaderV1, VersionedHeader, detect_version, CompatibilityMatrix};
use shadow_crypt::shared::version_dispatch::{AnyHeader, VersionMigrator};
use shadow_crypt::shared::algorithms::AlgorithmId;

#[test]
fn test_versioned_header_lifecycle() {
    // Create a version 1 header
    let header_v1 = HeaderV1::new(
        AlgorithmId::AesGcm256,
        [1u8; 16],  // salt
        [2u8; 12],  // nonce
    );
    
    // Test serialization
    let serialized = header_v1.serialize();
    assert!(!serialized.is_empty());
    
    // Test deserialization
    let (deserialized, _offset) = HeaderV1::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.version, 1);
    assert_eq!(deserialized.algorithm_id, AlgorithmId::AesGcm256);
    assert_eq!(deserialized.salt, [1u8; 16]);
    assert_eq!(deserialized.nonce, [2u8; 12]);
    
    // Test validation
    assert!(deserialized.validate().is_ok());
}

#[test]
fn test_version_detection() {
    let header_v1 = HeaderV1::new(AlgorithmId::AesGcm256, [1u8; 16], [2u8; 12]);
    let serialized = header_v1.serialize();
    
    // Test version detection from raw bytes
    let detected_version = detect_version(&serialized).unwrap();
    assert_eq!(detected_version, 1);
}

#[test]
fn test_any_header_dispatch() {
    // Create header using dispatch interface
    let header = AnyHeader::new_current(
        AlgorithmId::AesGcm256,
        [1u8; 16],
        [2u8; 12],
    );
    
    assert_eq!(header.version(), 1);
    assert_eq!(header.algorithm_id(), AlgorithmId::AesGcm256);
    
    // Test serialization through dispatch
    let serialized = header.serialize();
    assert!(!serialized.is_empty());
    
    // Test deserialization through dispatch
    let (deserialized, _offset) = AnyHeader::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.version(), 1);
    assert_eq!(deserialized.algorithm_id(), AlgorithmId::AesGcm256);
    
    // Test validation through dispatch
    assert!(deserialized.validate().is_ok());
}

#[test]
fn test_migration_capabilities() {
    let header = AnyHeader::new_current(AlgorithmId::AesGcm256, [1u8; 16], [2u8; 12]);
    
    // Test migration capabilities
    assert!(header.can_migrate_to(2));
    assert!(!header.can_migrate_to(100));
    
    // Test migration paths
    let paths = header.migration_paths();
    assert!(!paths.is_empty());
    assert!(paths.contains(&2));
    
    // Test migration planner
    assert!(VersionMigrator::can_migrate(1, 2));
    let plan = VersionMigrator::create_migration_plan(1, 2).unwrap();
    assert_eq!(plan.source_version, 1);
    assert_eq!(plan.target_version, 2);
}

#[test]
fn test_compatibility_matrix() {
    // Test reading capabilities
    assert!(CompatibilityMatrix::can_read(1));
    assert!(!CompatibilityMatrix::can_read(0));
    assert!(!CompatibilityMatrix::can_read(100));
    
    // Test writing capabilities
    assert!(CompatibilityMatrix::can_write(1));
    assert!(!CompatibilityMatrix::can_write(0));
    assert!(!CompatibilityMatrix::can_write(100));
    
    // Test migration capabilities
    assert!(CompatibilityMatrix::can_migrate(1, 2));
    assert!(!CompatibilityMatrix::can_migrate(0, 1));
    assert!(!CompatibilityMatrix::can_migrate(1, 100));
    
    // Test migration paths
    let paths = CompatibilityMatrix::migration_paths(1);
    assert!(!paths.is_empty());
    assert!(paths.contains(&2));
}

#[test]
fn test_version_specific_validation() {
    let mut header_v1 = HeaderV1::new(AlgorithmId::AesGcm256, [1u8; 16], [2u8; 12]);
    
    // Test valid header
    assert!(header_v1.validate().is_ok());
    
    // Test invalid magic
    header_v1.magic = *b"BADMAG";
    assert!(header_v1.validate().is_err());
    
    // Restore magic, test invalid version
    header_v1.magic = *b"SHADOW";
    header_v1.version = 2;
    assert!(header_v1.validate().is_err());
    
    // Restore version, test invalid algorithm for V1
    header_v1.version = 1;
    header_v1.algorithm_id = AlgorithmId::ChaCha20Poly1305;
    assert!(header_v1.validate().is_err());
}

#[test]
fn test_error_handling() {
    // Test insufficient data
    let insufficient_data = vec![0u8; 5];
    assert!(detect_version(&insufficient_data).is_err());
    assert!(HeaderV1::deserialize(&insufficient_data).is_err());
    assert!(AnyHeader::deserialize(&insufficient_data).is_err());
    
    // Test invalid magic
    let mut invalid_magic = vec![0u8; 100];
    invalid_magic[0..6].copy_from_slice(b"BADMAG");
    assert!(detect_version(&invalid_magic).is_err());
    
    // Test unsupported version in dispatch
    let mut unsupported_version = vec![0u8; 100];
    unsupported_version[0..6].copy_from_slice(b"SHADOW");
    unsupported_version[6..8].copy_from_slice(&100u16.to_le_bytes());
    assert!(AnyHeader::deserialize(&unsupported_version).is_err());
}

#[test]
fn test_roundtrip_compatibility() {
    // Test that we can create a header, serialize it, and deserialize it back
    // through both the versioned interface and the dispatch interface
    
    let original = HeaderV1::new(AlgorithmId::AesGcm256, [42u8; 16], [24u8; 12]);
    let serialized = original.serialize();
    
    // Test versioned interface roundtrip
    let (v1_deserialized, _) = HeaderV1::deserialize(&serialized).unwrap();
    assert_eq!(v1_deserialized.version, original.version);
    assert_eq!(v1_deserialized.salt, original.salt);
    assert_eq!(v1_deserialized.nonce, original.nonce);
    
    // Test dispatch interface roundtrip
    let (dispatch_deserialized, _) = AnyHeader::deserialize(&serialized).unwrap();
    assert_eq!(dispatch_deserialized.version(), original.version);
    assert_eq!(dispatch_deserialized.salt(), original.salt);
    assert_eq!(dispatch_deserialized.nonce(), original.nonce);
    
    // Test that both produce the same serialized output
    let v1_reserialized = v1_deserialized.serialize();
    let dispatch_reserialized = dispatch_deserialized.serialize();
    assert_eq!(v1_reserialized, dispatch_reserialized);
    assert_eq!(v1_reserialized, serialized);
}