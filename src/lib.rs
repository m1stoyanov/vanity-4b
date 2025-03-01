use std::sync::atomic::{AtomicU64, Ordering};

use keccak_asm::Digest;
use log::warn;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

pub mod cli;

pub const HEX_LOOKUP_TABLE: [u8; 256] = {
    let mut table = [0xFFu8; 256]; // Default all values to 0xFF (invalid)
    let mut i = 0;
    while i < 256 {
        table[i] = match i as u8 {
            b'0'..=b'9' => (i as u8) - b'0',      // Map '0'-'9' to 0-9
            b'a'..=b'f' => (i as u8) - b'a' + 10, // Map 'a'-'f' to 10-15
            b'A'..=b'F' => (i as u8) - b'A' + 10, // Map 'A'-'F' to 10-15
            _ => 0xFF,                            // Invalid characters
        };
        i += 1;
    }
    table
};

pub static HASH_COUNTER: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn calculate_keccak_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = keccak_asm::Keccak256::new();
    hasher.update(input);
    let output: [u8; 32] = hasher.finalize().into();
    output
}

#[inline]
fn compare_hash(hash: [u8; 32], pattern: &[u8]) -> bool {
    // Pattern is already validated so we dont check for != 0xFF
    match pattern.len() {
        0 => {
            // Empty pattern matches everything
            true
        }
        1 => {
            // Single hex character (high nibble of first byte)
            (hash[0] >> 4) == HEX_LOOKUP_TABLE[pattern[0] as usize]
        }
        2 => {
            // First byte only
            (hash[0] >> 4) == HEX_LOOKUP_TABLE[pattern[0] as usize]
                && (hash[0] & 0x0F) == HEX_LOOKUP_TABLE[pattern[1] as usize]
        }
        3 => {
            // First byte + high nibble of second
            (hash[0] >> 4) == HEX_LOOKUP_TABLE[pattern[0] as usize]
                && (hash[0] & 0x0F) == HEX_LOOKUP_TABLE[pattern[1] as usize]
                && (hash[1] >> 4) == HEX_LOOKUP_TABLE[pattern[2] as usize]
        }
        4 => {
            // First two bytes
            (hash[0] >> 4) == HEX_LOOKUP_TABLE[pattern[0] as usize]
                && (hash[0] & 0x0F) == HEX_LOOKUP_TABLE[pattern[1] as usize]
                && (hash[1] >> 4) == HEX_LOOKUP_TABLE[pattern[2] as usize]
                && (hash[1] & 0x0F) == HEX_LOOKUP_TABLE[pattern[3] as usize]
        }
        5 => {
            // Two bytes + high nibble of third
            (hash[0] >> 4) == HEX_LOOKUP_TABLE[pattern[0] as usize]
                && (hash[0] & 0x0F) == HEX_LOOKUP_TABLE[pattern[1] as usize]
                && (hash[1] >> 4) == HEX_LOOKUP_TABLE[pattern[2] as usize]
                && (hash[1] & 0x0F) == HEX_LOOKUP_TABLE[pattern[3] as usize]
                && (hash[2] >> 4) == HEX_LOOKUP_TABLE[pattern[4] as usize]
        }
        6 => {
            // Three bytes
            (hash[0] >> 4) == HEX_LOOKUP_TABLE[pattern[0] as usize]
                && (hash[0] & 0x0F) == HEX_LOOKUP_TABLE[pattern[1] as usize]
                && (hash[1] >> 4) == HEX_LOOKUP_TABLE[pattern[2] as usize]
                && (hash[1] & 0x0F) == HEX_LOOKUP_TABLE[pattern[3] as usize]
                && (hash[2] >> 4) == HEX_LOOKUP_TABLE[pattern[4] as usize]
                && (hash[2] & 0x0F) == HEX_LOOKUP_TABLE[pattern[5] as usize]
        }
        7 => {
            // Three bytes + high nibble of fourth
            (hash[0] >> 4) == HEX_LOOKUP_TABLE[pattern[0] as usize]
                && (hash[0] & 0x0F) == HEX_LOOKUP_TABLE[pattern[1] as usize]
                && (hash[1] >> 4) == HEX_LOOKUP_TABLE[pattern[2] as usize]
                && (hash[1] & 0x0F) == HEX_LOOKUP_TABLE[pattern[3] as usize]
                && (hash[2] >> 4) == HEX_LOOKUP_TABLE[pattern[4] as usize]
                && (hash[2] & 0x0F) == HEX_LOOKUP_TABLE[pattern[5] as usize]
                && (hash[3] >> 4) == HEX_LOOKUP_TABLE[pattern[6] as usize]
        }
        8 => {
            // Four bytes (most common case)
            (hash[0] >> 4) == HEX_LOOKUP_TABLE[pattern[0] as usize]
                && (hash[0] & 0x0F) == HEX_LOOKUP_TABLE[pattern[1] as usize]
                && (hash[1] >> 4) == HEX_LOOKUP_TABLE[pattern[2] as usize]
                && (hash[1] & 0x0F) == HEX_LOOKUP_TABLE[pattern[3] as usize]
                && (hash[2] >> 4) == HEX_LOOKUP_TABLE[pattern[4] as usize]
                && (hash[2] & 0x0F) == HEX_LOOKUP_TABLE[pattern[5] as usize]
                && (hash[3] >> 4) == HEX_LOOKUP_TABLE[pattern[6] as usize]
                && (hash[3] & 0x0F) == HEX_LOOKUP_TABLE[pattern[7] as usize]
        }
        _ => {
            panic!("Pattern longer than 4 bytes! This should never happen!");
        }
    }
}

pub fn generate_vanity_function_name(
    pattern: &[u8],
    name: &[u8],
    parameters: &[u8],
    range_start: u64,
    end: Option<u64>,
) -> Option<u64> {
    // Pre-allocate prefix and suffix buffers
    // First is just the name
    let prefix_buffer = name;
    // Second is the parameters part
    let mut suffix_buffer = Vec::with_capacity(parameters.len() + 2);
    suffix_buffer.push(b'(');
    suffix_buffer.extend_from_slice(parameters);
    suffix_buffer.push(b')');

    // Use thread-local buffer to avoid allocations
    thread_local! {
        static THREAD_BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(0));
        static DIGIT_BUFFER: std::cell::RefCell<[u8; 20]> = const { std::cell::RefCell::new([0u8; 20]) };
    }

    let range_end = end.unwrap_or(u64::MAX);

    (range_start..range_end).into_par_iter().find_any(|&num| {
        THREAD_BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            buffer.clear();
            buffer.extend_from_slice(prefix_buffer);

            if num > 0 {
                DIGIT_BUFFER.with(|digits| {
                    let mut digits = digits.borrow_mut();
                    let mut n = num;
                    let mut pos = 20;

                    // Convert directly to ASCII digits
                    while n > 0 {
                        pos -= 1;
                        digits[pos] = b'0' + (n % 10) as u8;
                        n /= 10;
                    }

                    buffer.extend_from_slice(&digits[pos..20]);
                });
            }

            buffer.extend_from_slice(&suffix_buffer);

            let hash = calculate_keccak_256(&buffer);

            // Increment hash counter (less frequently to reduce atomic contention)
            if (num & 0xFFFFF) == 0 {
                HASH_COUNTER.fetch_add(1048575, Ordering::Relaxed);
            }

            if compare_hash(hash, pattern) {
                let function_name = std::str::from_utf8(&buffer).unwrap();
                let function_name_hash = calculate_keccak_256(function_name.as_bytes());

                // Verify result
                if function_name_hash == hash {
                    true
                } else {
                    warn!("Result did not pass verification!");
                    warn!(
                        "Candidate {:?} does not match {:?}",
                        &hash[..4],
                        &function_name_hash[..4]
                    );
                    false
                }
            } else {
                false
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        HEX_LOOKUP_TABLE, calculate_keccak_256, compare_hash, generate_vanity_function_name,
    };

    #[test]
    fn test_calculate_keccak_256() {
        let input = b"transfer(address,uint256)";
        let expected = [
            // Known correct hash for "transfer(address,uint256)"
            0xa9, 0x05, 0x9c, 0xbb, /* remaining bytes... */
        ];
        assert_eq!(calculate_keccak_256(input)[..4], expected);
    }

    #[test]
    fn test_compare_hash() {
        // Test various pattern lengths (1-8 chars)
        let hash = [
            0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        assert!(compare_hash(hash, b"1")); // Just high nibble of first byte
        assert!(compare_hash(hash, b"12")); // First byte
        assert!(!compare_hash(hash, b"13")); // Should fail

        // Test complete 4-byte pattern
        assert!(compare_hash(hash, b"12345678"));
    }

    #[test]
    fn test_generate_vanity_function_name() {
        // Test with known solution
        let solution = generate_vanity_function_name(
            b"1234",            // Pattern to match
            b"transfer",        // Function name
            b"address,uint256", // Parameters
            0,                  // Start range
            Some(1000000),      // End range (limit for faster test)
        );

        assert!(solution.is_some());

        // Verify the solution
        let solution_index = solution.unwrap();
        let function_name = format!("transfer{}(address,uint256)", solution_index);
        let hash = calculate_keccak_256(function_name.as_bytes());

        assert_eq!(format!("{:02x}{:02x}", hash[0], hash[1]), "1234");
    }

    #[test]
    fn test_empty_pattern() {
        // Empty pattern should match anything
        let solution = generate_vanity_function_name(
            b"",     // Empty pattern
            b"test", // Function name
            b"",     // No parameters
            0,
            Some(10), // Should find solution quickly
        );

        assert!(solution.is_some());
        assert_eq!(solution.unwrap(), 0); // Should return 0 as first match
    }

    #[test]
    fn test_empty_function_name() {
        // Not a valid Solidity function, but should still hash
        let solution = generate_vanity_function_name(
            b"1234",
            b"", // Empty function name
            b"",
            0,
            Some(10000),
        );

        // The test should either find a solution or reach the end
        if let Some(solution_index) = solution {
            let function_name = format!("{}()", solution_index);
            let hash = calculate_keccak_256(function_name.as_bytes());
            assert_eq!(format!("{:02x}{:02x}", hash[0], hash[1]), "1234");
        }
    }

    #[test]
    fn test_long_inputs() {
        let long_name = "veryLongFunctionNameThatMightCauseIssuesIfNotHandledProperly";
        let long_params = "address,uint256,string,bytes32,bool,address[],uint256[]";

        let solution = generate_vanity_function_name(
            b"1234",
            long_name.as_bytes(),
            long_params.as_bytes(),
            0,
            Some(10000), // Limit for test speed
        );

        // Either finds a solution or reaches the limit without panicking
        if let Some(solution_index) = solution {
            let function_name = format!("{}{}({})", long_name, solution_index, long_params);
            let hash = calculate_keccak_256(function_name.as_bytes());
            assert_eq!(format!("{:02x}{:02x}", hash[0], hash[1]), "1234");
        }
    }

    #[test]
    fn test_full_pattern_matching() {
        // Prepare known function that produces a specific hash
        let fn_name = "transfer";
        let fn_params = "address,uint256";
        let fn_suffix = "12345"; // Known suffix that produces desired hash

        let full_fn = format!("{}{}({})", fn_name, fn_suffix, fn_params);
        let hash = calculate_keccak_256(full_fn.as_bytes());

        // Extract the pattern from the hash
        let pattern = format!("{:02x}{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2], hash[3]);

        // Try to find the function with our generator
        let solution = generate_vanity_function_name(
            pattern.as_bytes(),
            fn_name.as_bytes(),
            fn_params.as_bytes(),
            0,
            Some(100000), // Should find the match within this range
        );

        assert!(solution.is_some());
        assert_eq!(solution.unwrap(), 12345);
    }

    #[test]
    fn test_hex_lookup_table() {
        // Test valid hex characters
        assert_eq!(HEX_LOOKUP_TABLE[b'0' as usize], 0);
        assert_eq!(HEX_LOOKUP_TABLE[b'9' as usize], 9);
        assert_eq!(HEX_LOOKUP_TABLE[b'a' as usize], 10);
        assert_eq!(HEX_LOOKUP_TABLE[b'f' as usize], 15);
        assert_eq!(HEX_LOOKUP_TABLE[b'A' as usize], 10);
        assert_eq!(HEX_LOOKUP_TABLE[b'F' as usize], 15);

        // Test invalid characters
        assert_eq!(HEX_LOOKUP_TABLE[b'g' as usize], 0xFF);
        assert_eq!(HEX_LOOKUP_TABLE[b'/' as usize], 0xFF);
    }
}
