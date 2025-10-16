// shadow-core/src/validation/entropy.rs
// Professional-grade password entropy estimation
// Based on NIST SP 800-63B and modern cryptographic research

use crate::types::SecureString;
use crate::errors::ValidationError;
use crate::format::MIN_PASSWORD_ENTROPY_BITS;
use std::collections::HashMap;

/// Character frequency analysis for entropy calculation
const ENGLISH_LETTER_FREQUENCIES: &[(char, f64)] = &[
    ('e', 0.127), ('t', 0.091), ('a', 0.082), ('o', 0.075), ('i', 0.070),
    ('n', 0.067), ('s', 0.063), ('h', 0.061), ('r', 0.060), ('d', 0.043),
    ('l', 0.040), ('c', 0.028), ('u', 0.028), ('m', 0.024), ('w', 0.023),
    ('f', 0.022), ('g', 0.020), ('y', 0.020), ('p', 0.019), ('b', 0.013),
    ('v', 0.010), ('k', 0.008), ('j', 0.002), ('x', 0.001), ('q', 0.001), ('z', 0.001),
];

/// Common password patterns that reduce entropy
const COMMON_PATTERNS: &[&str] = &[
    "123", "abc", "qwe", "asd", "zxc", "password", "admin", "login",
    "000", "111", "222", "333", "444", "555", "666", "777", "888", "999",
];

/// Validate password entropy using professional cryptographic standards
/// Pure function - no side effects
pub fn validate_password_entropy(password: &SecureString) -> Result<(), ValidationError> {
    let entropy = estimate_password_entropy_advanced(password.as_str());
    
    if entropy < MIN_PASSWORD_ENTROPY_BITS {
        return Err(ValidationError::WeakPassword {
            reason: format!(
                "Password entropy {:.1} bits is below required minimum of {:.1} bits. Use a longer passphrase or more random characters.",
                entropy, MIN_PASSWORD_ENTROPY_BITS
            ),
        });
    }
    
    Ok(())
}

/// Advanced entropy estimation based on multiple factors
/// Considers patterns, repetitions, frequency analysis, and common passwords
fn estimate_password_entropy_advanced(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    
    // Start with base character set entropy
    let base_entropy = calculate_character_set_entropy(password);
    
    // Apply reductions for patterns and weaknesses
    let pattern_reduction = calculate_pattern_reduction(password);
    let repetition_reduction = calculate_repetition_reduction(password);
    let frequency_reduction = calculate_frequency_reduction(password);
    let dictionary_reduction = calculate_dictionary_reduction(password);
    
    // Apply the most significant reduction (not cumulative to avoid over-penalizing)
    let max_reduction = pattern_reduction
        .max(repetition_reduction)
        .max(frequency_reduction)
        .max(dictionary_reduction);
    
    // Ensure we don't go below a minimal entropy floor
    let reduced_entropy = base_entropy * (1.0 - max_reduction);
    reduced_entropy.max(password.len() as f64 * 0.5) // Minimum 0.5 bits per character
}

/// Calculate base entropy from character set diversity
fn calculate_character_set_entropy(password: &str) -> f64 {
    let mut char_sets = 0;
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut has_unicode = false;
    
    for ch in password.chars() {
        if ch.is_ascii_lowercase() && !has_lower {
            has_lower = true;
            char_sets += 26;
        } else if ch.is_ascii_uppercase() && !has_upper {
            has_upper = true;
            char_sets += 26;
        } else if ch.is_ascii_digit() && !has_digit {
            has_digit = true;
            char_sets += 10;
        } else if ch.is_ascii_punctuation() && !has_symbol {
            has_symbol = true;
            char_sets += 32; // Common symbols
        } else if !ch.is_ascii() && !has_unicode {
            has_unicode = true;
            char_sets += 1000; // Rough estimate for Unicode characters
        }
    }
    
    if char_sets == 0 {
        return 0.0;
    }
    
    password.chars().count() as f64 * (char_sets as f64).log2()
}

/// Detect and penalize common patterns
fn calculate_pattern_reduction(password: &str) -> f64 {
    let mut max_pattern_score = 0.0_f64;
    
    // Check for sequential patterns
    if has_sequential_pattern(password) {
        max_pattern_score = max_pattern_score.max(0.7); // 70% reduction
    }
    
    // Check for repetitive patterns
    if has_repetitive_pattern(password) {
        max_pattern_score = max_pattern_score.max(0.6); // 60% reduction
    }
    
    // Check for keyboard patterns
    if has_keyboard_pattern(password) {
        max_pattern_score = max_pattern_score.max(0.8); // 80% reduction
    }
    
    // Check for common substrings
    for pattern in COMMON_PATTERNS {
        if password.to_lowercase().contains(pattern) {
            max_pattern_score = max_pattern_score.max(0.5); // 50% reduction
        }
    }
    
    max_pattern_score
}

/// Detect sequential patterns (abc, 123, etc.)
fn has_sequential_pattern(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < 3 {
        return false;
    }
    
    for window in chars.windows(3) {
        if window.len() == 3 {
            let a = window[0] as u32;
            let b = window[1] as u32;
            let c = window[2] as u32;
            
            // Check if consecutive
            if (b == a + 1 && c == b + 1) || (b == a - 1 && c == b - 1) {
                return true;
            }
        }
    }
    
    false
}

/// Detect repetitive patterns (aaa, 111, abcabc, etc.)
fn has_repetitive_pattern(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    
    // Check for repeated characters
    for window in chars.windows(3) {
        if window[0] == window[1] && window[1] == window[2] {
            return true;
        }
    }
    
    // Check for repeated substrings
    let len = chars.len();
    for pattern_len in 2..=(len / 2) {
        for start in 0..=(len - pattern_len * 2) {
            let pattern = &chars[start..start + pattern_len];
            let next = &chars[start + pattern_len..start + pattern_len * 2];
            if pattern == next {
                return true;
            }
        }
    }
    
    false
}

/// Detect keyboard patterns (qwerty, asdf, etc.)
fn has_keyboard_pattern(password: &str) -> bool {
    let keyboard_rows = &[
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
    ];
    
    let lower_password = password.to_lowercase();
    
    for row in keyboard_rows {
        for window_size in 3..=6 {
            for start in 0..=(row.len().saturating_sub(window_size)) {
                let pattern = &row[start..start + window_size];
                if lower_password.contains(pattern) {
                    return true;
                }
                // Also check reverse
                let reverse: String = pattern.chars().rev().collect();
                if lower_password.contains(&reverse) {
                    return true;
                }
            }
        }
    }
    
    false
}

/// Calculate reduction based on character repetition
fn calculate_repetition_reduction(password: &str) -> f64 {
    let mut char_counts = HashMap::new();
    let total_chars = password.chars().count();
    
    for ch in password.chars() {
        *char_counts.entry(ch).or_insert(0) += 1;
    }
    
    // Calculate repetition ratio
    let max_repetition = char_counts.values().max().unwrap_or(&1);
    let repetition_ratio = *max_repetition as f64 / total_chars as f64;
    
    if repetition_ratio > 0.5 {
        repetition_ratio * 0.8 // Up to 80% reduction for highly repetitive passwords
    } else {
        0.0
    }
}

/// Calculate reduction based on character frequency analysis
fn calculate_frequency_reduction(password: &str) -> f64 {
    let mut frequency_score = 0.0;
    let char_count = password.chars().count() as f64;
    
    for ch in password.chars() {
        if let Some((_, freq)) = ENGLISH_LETTER_FREQUENCIES.iter().find(|(c, _)| *c == ch.to_ascii_lowercase()) {
            frequency_score += freq;
        }
    }
    
    let avg_frequency = frequency_score / char_count;
    
    // High frequency = common letters = reduced entropy
    if avg_frequency > 0.06 {
        (avg_frequency - 0.06) * 5.0 // Scale the reduction
    } else {
        0.0
    }
}

/// Calculate reduction for dictionary words and common passwords
fn calculate_dictionary_reduction(password: &str) -> f64 {
    let lower_password = password.to_lowercase();
    
    // Check against common passwords (simplified for this example)
    let common_passwords = &[
        "password", "123456", "password123", "admin", "qwerty", "letmein",
        "welcome", "monkey", "dragon", "master", "hello", "login",
    ];
    
    for common in common_passwords {
        if lower_password.contains(common) || lower_password == *common {
            return 0.9; // 90% reduction for containing common passwords
        }
    }
    
    // Check for dictionary words (simplified - in production, use a proper dictionary)
    let common_words = &[
        "computer", "internet", "security", "system", "network", "database",
        "application", "software", "hardware", "technology", "digital",
    ];
    
    for word in common_words {
        if lower_password.contains(word) {
            return 0.6; // 60% reduction for containing dictionary words
        }
    }
    
    0.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_strong_password() {
        let strong_password = SecureString::new("My$tr0ng!P@ssw0rd#2024".to_string());
        let result = validate_password_entropy(&strong_password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_weak_password() {
        let weak_password = SecureString::new("password123".to_string());
        let result = validate_password_entropy(&weak_password);
        assert!(matches!(result, Err(ValidationError::WeakPassword { .. })));
    }

    #[test]
    fn test_validate_short_random_password() {
        let short_password = SecureString::new("aB3$".to_string());
        let result = validate_password_entropy(&short_password);
        assert!(matches!(result, Err(ValidationError::WeakPassword { .. })));
    }

    #[test]
    fn test_validate_long_passphrase() {
        let passphrase = SecureString::new("correct horse battery staple magnificent journey".to_string());
        let result = validate_password_entropy(&passphrase);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pattern_detection() {
        assert!(has_sequential_pattern("abc123"));
        assert!(has_sequential_pattern("321cba"));
        assert!(!has_sequential_pattern("randomtext"));
        
        assert!(has_repetitive_pattern("aaabbb"));
        assert!(has_repetitive_pattern("abcabc"));
        assert!(!has_repetitive_pattern("abcdef"));
        
        assert!(has_keyboard_pattern("qwerty"));
        assert!(has_keyboard_pattern("asdf"));
        assert!(!has_keyboard_pattern("randomkeys"));
    }

    #[test]
    fn test_entropy_calculation() {
        // Very weak password
        let entropy1 = estimate_password_entropy_advanced("password");
        assert!(entropy1 < MIN_PASSWORD_ENTROPY_BITS);
        
        // Strong random password
        let entropy2 = estimate_password_entropy_advanced("Kj8#mP9$nQ2@wE5!");
        assert!(entropy2 >= MIN_PASSWORD_ENTROPY_BITS);
        
        // Good passphrase
        let entropy3 = estimate_password_entropy_advanced("The quick brown fox jumps over 13 lazy dogs!");
        assert!(entropy3 >= MIN_PASSWORD_ENTROPY_BITS);
    }
}