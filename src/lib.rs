use std::{
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
};

use log::info;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tiny_keccak::{Hasher, Keccak};

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
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

#[inline]
fn nibble_matches(byte: u8, pattern_hi: u8, pattern_lo: u8) -> bool {
    (byte >> 4) == HEX_LOOKUP_TABLE[pattern_hi as usize]
        && (byte & 0x0F) == HEX_LOOKUP_TABLE[pattern_lo as usize]
}

pub fn generate_vanity_function_name(pattern: &[u8], name: &[u8], parameters: &[u8]) {
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
    }

    (0_u64..u64::MAX).into_par_iter().find_any(|&num| {
        THREAD_BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            buffer.clear();
            buffer.extend_from_slice(prefix_buffer);
            if num > 0 {
                write!(&mut buffer, "{}", num).unwrap();
            }
            buffer.extend_from_slice(&suffix_buffer);

            let hash = calculate_keccak_256(&buffer);

            // Increment hash counter (less frequently to reduce atomic contention)
            if (num & 0x3FF) == 0 {
                HASH_COUNTER.fetch_add(1024, Ordering::Relaxed);
            }

            // Compare hash bytes directly with pattern
            if hash
                .iter()
                .take(4)
                .zip(pattern.chunks(2))
                .all(|(byte, pattern_pair)| nibble_matches(*byte, pattern_pair[0], pattern_pair[1]))
            {
                let function_name = std::str::from_utf8(&buffer).unwrap();
                let signature =
                    format!("0x{:02x}{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2], hash[3]);

                info!("Vanity function name found:");
                info!("Signature: {}", signature);
                info!("Function name: {}", function_name);
                true
            } else {
                false
            }
        })
    });
}
