use std::io::Write;

use log::info;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tiny_keccak::{Hasher, Keccak};

#[inline]
pub fn calculate_keccak_256(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

#[inline]
fn hex_to_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("Invalid hex character"),
    }
}

#[inline]
fn nibble_matches(byte: u8, pattern_hi: u8, pattern_lo: u8) -> bool {
    (byte >> 4) == hex_to_val(pattern_hi) && (byte & 0x0F) == hex_to_val(pattern_lo)
}

pub fn generate_vanity_function_name(pattern: &[u8], name: &[u8], parameters: &[u8]) {
    // Pre-allocate prefix and suffix buffers
    let buffer_len = name.len() + parameters.len() + 22;
    // First is just the name
    let prefix_buffer = name;
    // Second is the parameters part
    let mut suffix_buffer = Vec::with_capacity(parameters.len() + 2);
    suffix_buffer.push(b'(');
    suffix_buffer.extend_from_slice(parameters);
    suffix_buffer.push(b')');

    (0_u64..u64::MAX).into_par_iter().find_any(|&num| {
        let mut buffer = Vec::with_capacity(buffer_len);
        buffer.extend_from_slice(prefix_buffer);
        if num > 0 {
            write!(&mut buffer, "{}", num).unwrap();
        }
        buffer.extend_from_slice(&suffix_buffer);

        let hash = calculate_keccak_256(&buffer);

        // Compare hash bytes directly with pattern
        if hash
            .iter()
            .take(4)
            .zip(pattern.chunks(2))
            .all(|(byte, pattern_pair)| nibble_matches(*byte, pattern_pair[0], pattern_pair[1]))
        {
            let function_name = std::str::from_utf8(&buffer).unwrap();
            let signature = format!(
                "0x{:02x}{:02x}{:02x}{:02x}",
                hash[0], hash[1], hash[2], hash[3]
            );

            info!("Vanity function name found:");
            info!("Signature: {}", signature);
            info!("Function name: {}", function_name);
            true
        } else {
            false
        }
    });
}
