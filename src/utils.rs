use std::io::Write;

use const_hex::encode;
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

        // Compare with pattern - only convert to hex if needed
        if encode(&hash[..4]).as_bytes().starts_with(pattern) {
            let function_name = std::str::from_utf8(&buffer).unwrap();
            let signature = format!("0x{}", encode(&hash[..4]));

            info!("Vanity function name found:");
            info!("Signature: {}", signature);
            info!("Function name: {}", function_name);
            true
        } else {
            false
        }
    });
}
