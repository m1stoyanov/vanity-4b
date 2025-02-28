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
    num_cores: Option<usize>,
) {
    // Pre-allocate prefix and suffix buffers
    // First is just the name
    let prefix_buffer = name;
    // Second is the parameters part
    let mut suffix_buffer = Vec::with_capacity(parameters.len() + 2);
    suffix_buffer.push(b'(');
    suffix_buffer.extend_from_slice(parameters);
    suffix_buffer.push(b')');

    // Configure thread pool
    let available_cores = num_cpus::get();
    let cores_to_use = match num_cores {
        Some(cores) => cores,
        None => {
            if available_cores > 1 {
                available_cores / 2
            } else {
                1
            }
        }
    };

    rayon::ThreadPoolBuilder::new()
        .num_threads(cores_to_use)
        .build_global()
        .expect("Failed to build thread pool");

    info!("Using {} of {} available cores for processing", cores_to_use, available_cores);

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
            if (num & 0xFFFFF) == 0 {
                HASH_COUNTER.fetch_add(1048575, Ordering::Relaxed);
            }

            if compare_hash(hash, pattern) {
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
