use const_hex::encode;
use log::info;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tiny_keccak::{Hasher, Keccak};

#[inline]
pub fn calculate_keccak_256(input: &str) -> String {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input.as_bytes());
    hasher.finalize(&mut output);
    format!("0x{}", encode(output))
}

pub fn generate_vanity_function_name(pattern: &str, name: &str, parameters: &str) {
    (0_u64..u64::MAX).into_par_iter().find_any(|&num| {
        let mut candidate = String::with_capacity(name.len() + parameters.len() + 22); //20 characters u64::MAX + "()"
        if num > 0 {
            candidate.push_str(&format!("{}{}({})", name, num, parameters));
        } else {
            candidate.push_str(&format!("{}({})", name, parameters));
        }

        let hash = calculate_keccak_256(&candidate)[..10].to_string();

        if hash.starts_with(pattern) {
            info!("Vanity function name found:");
            info!("Signature: {}", hash);
            info!("Function name: {}", candidate);
            true // early exit
        } else {
            false
        }
    });
}
