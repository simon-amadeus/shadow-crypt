// shadow-core/src/validation/duplicates.rs
// Duplicate detection and content comparison functions
// All code related to detecting duplicate content lives here

use subtle::ConstantTimeEq;

/// Constant-time equality comparison for security-sensitive data
/// Pure function that prevents timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Check if a content hash already exists in a list of known hashes
/// Pure function - no side effects
pub fn check_content_duplicate(content_hash: &[u8; 32], known_hashes: &[[u8; 32]]) -> bool {
    known_hashes
        .iter()
        .any(|hash| constant_time_eq(content_hash, hash))
}

/// Find all duplicate hashes in a collection
/// Pure function - returns indices of duplicates
pub fn find_duplicate_hashes(hashes: &[[u8; 32]]) -> Vec<(usize, usize)> {
    let mut duplicates = Vec::new();

    for (i, hash_a) in hashes.iter().enumerate() {
        for (j, hash_b) in hashes.iter().enumerate().skip(i + 1) {
            if constant_time_eq(hash_a, hash_b) {
                duplicates.push((i, j));
            }
        }
    }

    duplicates
}

/// Count unique hashes in a collection
/// Pure function - returns count of unique hashes
pub fn count_unique_hashes(hashes: &[[u8; 32]]) -> usize {
    if hashes.is_empty() {
        return 0;
    }

    let mut unique_count = 0;
    let mut processed = vec![false; hashes.len()];

    for (i, hash) in hashes.iter().enumerate() {
        if processed[i] {
            continue;
        }

        unique_count += 1;
        processed[i] = true;

        // Mark all duplicates of this hash as processed
        for (j, other_hash) in hashes.iter().enumerate().skip(i + 1) {
            if !processed[j] && constant_time_eq(hash, other_hash) {
                processed[j] = true;
            }
        }
    }

    unique_count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_content_duplicate_found() {
        let target_hash = [1u8; 32];
        let known_hashes = vec![
            [0u8; 32], [1u8; 32], // This matches
            [2u8; 32],
        ];

        let result = check_content_duplicate(&target_hash, &known_hashes);
        assert!(result);
    }

    #[test]
    fn test_check_content_duplicate_not_found() {
        let target_hash = [99u8; 32];
        let known_hashes = vec![[0u8; 32], [1u8; 32], [2u8; 32]];

        let result = check_content_duplicate(&target_hash, &known_hashes);
        assert!(!result);
    }

    #[test]
    fn test_check_content_duplicate_empty_list() {
        let target_hash = [1u8; 32];
        let known_hashes = vec![];

        let result = check_content_duplicate(&target_hash, &known_hashes);
        assert!(!result);
    }

    #[test]
    fn test_find_duplicate_hashes_none() {
        let hashes = vec![[0u8; 32], [1u8; 32], [2u8; 32]];

        let duplicates = find_duplicate_hashes(&hashes);
        assert!(duplicates.is_empty());
    }

    #[test]
    fn test_find_duplicate_hashes_some() {
        let hashes = vec![
            [0u8; 32], [1u8; 32], [0u8; 32], // Duplicate of index 0
            [2u8; 32], [1u8; 32], // Duplicate of index 1
        ];

        let duplicates = find_duplicate_hashes(&hashes);
        assert_eq!(duplicates.len(), 2);
        assert!(duplicates.contains(&(0, 2))); // First and third are same
        assert!(duplicates.contains(&(1, 4))); // Second and fifth are same
    }

    #[test]
    fn test_find_duplicate_hashes_empty() {
        let hashes = vec![];
        let duplicates = find_duplicate_hashes(&hashes);
        assert!(duplicates.is_empty());
    }

    #[test]
    fn test_count_unique_hashes_all_unique() {
        let hashes = vec![[0u8; 32], [1u8; 32], [2u8; 32]];

        let count = count_unique_hashes(&hashes);
        assert_eq!(count, 3);
    }

    #[test]
    fn test_count_unique_hashes_with_duplicates() {
        let hashes = vec![
            [0u8; 32], [1u8; 32], [0u8; 32], // Duplicate
            [2u8; 32], [1u8; 32], // Duplicate
            [0u8; 32], // Another duplicate
        ];

        let count = count_unique_hashes(&hashes);
        assert_eq!(count, 3); // Only 3 unique: [0], [1], [2]
    }

    #[test]
    fn test_count_unique_hashes_empty() {
        let hashes = vec![];
        let count = count_unique_hashes(&hashes);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_count_unique_hashes_all_same() {
        let hashes = vec![[42u8; 32], [42u8; 32], [42u8; 32]];

        let count = count_unique_hashes(&hashes);
        assert_eq!(count, 1);
    }
}
