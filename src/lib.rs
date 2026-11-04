#[cfg(target_arch = "x86_64")]
pub mod keccak_avx2;

use std::sync::atomic::{AtomicU64, Ordering};

use log::warn;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

/// Whether the current CPU can use the AVX2 Keccak kernel (checked once).
/// Only meaningful on x86-64; the static is omitted elsewhere to avoid a
/// dead-code warning.
#[cfg(target_arch = "x86_64")]
static AVX2: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Build the const initializer for a per-thread candidate buffer.
const fn init_buf() -> std::cell::RefCell<Vec<u8>> {
    std::cell::RefCell::new(Vec::new())
}

thread_local! {
    /// Per-thread reusable candidate buffers. They grow to the needed size on
    /// first use and are then reused (never reallocated, never re-zeroed),
    /// which avoids zeroing a 512-byte stack array for every pair. `build_candidate`
    /// overwrites the whole `[0..total]` region we read, so the rest is unused.
    static CAND1: std::cell::RefCell<Vec<u8>> = const { init_buf() };
    static CAND2: std::cell::RefCell<Vec<u8>> = const { init_buf() };
}

#[cfg(target_arch = "x86_64")]
thread_local! {
    /// 136-byte buffer + last digit count + last hasher id for the templated AVX2
    /// fast path. The pre-padded template is re-copied when the digit count
    /// changes *or* the creating hasher is a new one (see `TemplatedHasher`
    /// epoch), so a buffer left over from a previous search is re-seeded.
    static TL_BUF1: std::cell::RefCell<([u8; 136], usize, u64)> =
        const { std::cell::RefCell::new(([0u8; 136], 0, u64::MAX)) };
    static TL_BUF2: std::cell::RefCell<([u8; 136], usize, u64)> =
        const { std::cell::RefCell::new(([0u8; 136], 0, u64::MAX)) };
}

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
    #[cfg(target_arch = "x86_64")]
    {
        if *AVX2.get_or_init(keccak_avx2::is_avx2) {
            // SAFETY: AVX2 was detected on this CPU.
            return unsafe { keccak_avx2::keccak256(input) };
        }
    }
    keccak_asm::Keccak256::digest(input).into()
}

/// Hash two inputs; on AVX2 CPUs the two-way kernel hashes both in one pass
/// (faster than two separate hashes). Falls back to two independent hashes.
///
/// The two-way kernel only supports single-block inputs (< 136 bytes each);
/// longer inputs are hashed with the (multi-block-capable) single AVX2 kernel,
/// and on non-AVX2 CPUs with `keccak-asm`.
#[inline]
pub fn calculate_keccak_256x2(a: &[u8], b: &[u8]) -> ([u8; 32], [u8; 32]) {
    #[cfg(target_arch = "x86_64")]
    {
        if *AVX2.get_or_init(keccak_avx2::is_avx2) {
            // SAFETY: AVX2 was detected on this CPU.
            if a.len() < keccak_avx2::RATE && b.len() < keccak_avx2::RATE {
                return unsafe { keccak_avx2::keccak256x2(a, b) };
            }
            // Multi-block inputs: hash each with the single AVX2 kernel
            // (faster than the portable `keccak-asm` fallback).
            return (unsafe { keccak_avx2::keccak256(a) }, unsafe { keccak_avx2::keccak256(b) });
        }
    }
    (keccak_asm::Keccak256::digest(a).into(), keccak_asm::Keccak256::digest(b).into())
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
    // The hash input is always `name + digits(num) + "(params)"`.
    let prefix = name;
    let mut suffix: Vec<u8> = Vec::with_capacity(parameters.len() + 2);
    suffix.push(b'(');
    suffix.extend_from_slice(parameters);
    suffix.push(b')');

    let range_end = end.unwrap_or(u64::MAX);
    let count = range_end.saturating_sub(range_start);
    let n_pairs = count / 2 + count % 2;

    // Fast path: AVX2 + every candidate is a single Keccak block (< 136 bytes).
    // The padding is precomputed per digit count, so only the digits are patched
    // per candidate, and the method-id prefix is checked before squeezing the
    // full digest. Falls back to the generic path elsewhere.
    let use_templated: bool = {
        #[cfg(target_arch = "x86_64")]
        {
            *AVX2.get_or_init(keccak_avx2::is_avx2) && prefix.len() + 20 + suffix.len() < 136
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    };

    if use_templated {
        let hasher = keccak_avx2::TemplatedHasher::new(prefix, &suffix, pattern);
        (0..n_pairs).into_par_iter().find_map_any(|i| {
            let num1 = range_start + 2 * i;
            let num2 = num1 + 1;
            TL_BUF1.with(|cell| {
                let (buf1, last1, ep1) = &mut *cell.borrow_mut();
                let h1 = unsafe { hasher.hash_if_match(buf1, last1, ep1, num1) };
                if (i & 0xFFFFF) == 0 {
                    let add = if num2 < range_end { 2_097_152 } else { 1_048_576 };
                    HASH_COUNTER.fetch_add(add, Ordering::Relaxed);
                }
                if num2 < range_end {
                    TL_BUF2.with(|cell2| {
                        let (buf2, last2, ep2) = &mut *cell2.borrow_mut();
                        let h2 = unsafe { hasher.hash_if_match(buf2, last2, ep2, num2) };
                        if let Some(_h) = h1.filter(|h| verify_candidate(prefix, &suffix, num1, *h))
                        {
                            return Some(num1);
                        }
                        if let Some(_h) = h2.filter(|h| verify_candidate(prefix, &suffix, num2, *h))
                        {
                            return Some(num2);
                        }
                        None
                    })
                } else if let Some(h) = h1 {
                    if verify_candidate(prefix, &suffix, num1, h) { Some(num1) } else { None }
                } else {
                    None
                }
            })
        })
    } else {
        // A u64 has at most 20 decimal digits, so the input never exceeds this.
        let max_len = prefix.len() + 20 + suffix.len();
        // Process two consecutive candidates per step so the AVX2 two-way kernel
        // can hash both in a single pass (faster than two separate hashes).
        //
        // We iterate over *pair indices* (0, 1, 2, …) because `StepBy<Range<u64>>`
        // does not implement `IntoParallelIterator`. Candidate buffers are
        // thread-local and reused, so no per-pair allocation or zeroing.
        (0..n_pairs).into_par_iter().find_map_any(|i| {
            let num1 = range_start + 2 * i;
            let num2 = num1 + 1;
            CAND1.with(|c1_cell| {
                let mut c1 = c1_cell.borrow_mut();
                if c1.len() < max_len {
                    c1.resize(max_len, 0);
                }
                let t1 = build_candidate(&mut c1[..], prefix, &suffix, num1);
                if num2 < range_end {
                    CAND2.with(|c2_cell| {
                        let mut c2 = c2_cell.borrow_mut();
                        if c2.len() < max_len {
                            c2.resize(max_len, 0);
                        }
                        let t2 = build_candidate(&mut c2[..], prefix, &suffix, num2);
                        evaluate2(&c1[..t1], &c2[..t2], pattern, num1, num2, i)
                    })
                } else {
                    evaluate(&c1[..t1], pattern, num1, i)
                }
            })
        })
    }
}

/// Re-hash a candidate that matched the pattern and confirm the full digest
/// (a cheap safety check; the match is otherwise trusted).
///
/// Uses the portable `keccak-asm` implementation for independent verification,
/// so a bug in the AVX2 kernel would be caught here.
#[inline]
fn verify(input: &[u8], hash: [u8; 32]) -> bool {
    let function_name = std::str::from_utf8(input).unwrap();
    let function_name_hash: [u8; 32] =
        keccak_asm::Keccak256::digest(function_name.as_bytes()).into();

    if function_name_hash == hash {
        true
    } else {
        warn!("Result did not pass verification!");
        warn!("Candidate {:?} does not match {:?}", &hash[..4], &function_name_hash[..4]);
        false
    }
}

/// Rebuild `name + digits(num) + suffix` and verify `hash` against it with an
/// independent keccak-asm digest. This is the safety net for the templated fast
/// path: unlike hashing the thread-local buffer, it hashes a *freshly built*
/// candidate, so a stale buffer left over from a previous search cannot cause a
/// false positive. It only runs on a prefix match (~1 in 65536), so the
/// per-call allocation is negligible.
#[inline]
fn verify_candidate(name: &[u8], suffix: &[u8], num: u64, hash: [u8; 32]) -> bool {
    let mut buf = vec![0u8; name.len() + 20 + suffix.len()];
    let total = build_candidate(&mut buf, name, suffix, num);
    verify(&buf[..total], hash)
}

/// Hash a single candidate and check it against the pattern.
/// Returns `Some(num)` if the candidate matches.
#[inline]
fn evaluate(input: &[u8], pattern: &[u8], num: u64, pair_idx: u64) -> Option<u64> {
    let hash = calculate_keccak_256(input);

    // Increment hash counter (less frequently to reduce atomic contention).
    // One candidate per call → add 2^20 every 2^20 pairs.
    if (pair_idx & 0xFFFFF) == 0 {
        HASH_COUNTER.fetch_add(1048576, Ordering::Relaxed);
    }

    if compare_hash(hash, pattern) { verify(input, hash).then_some(num) } else { None }
}

/// Hash two candidates (two-way kernel on AVX2) and check both against the
/// pattern, returning `Some(num)` for the first match.
#[inline]
fn evaluate2(
    input1: &[u8],
    input2: &[u8],
    pattern: &[u8],
    num1: u64,
    num2: u64,
    pair_idx: u64,
) -> Option<u64> {
    let (h1, h2) = calculate_keccak_256x2(input1, input2);

    // Two candidates were hashed this step → add 2×2^20 every 2^20 pairs.
    if (pair_idx & 0xFFFFF) == 0 {
        HASH_COUNTER.fetch_add(2097152, Ordering::Relaxed);
    }

    if compare_hash(h1, pattern) && verify(input1, h1) {
        return Some(num1);
    }
    if compare_hash(h2, pattern) && verify(input2, h2) {
        return Some(num2);
    }
    None
}

/// Write `name + digits(num) + suffix` into `buf` (which must have room for
/// `name.len() + 20 + suffix.len()` bytes) and return the total length.
#[inline]
fn build_candidate(buf: &mut [u8], name: &[u8], suffix: &[u8], num: u64) -> usize {
    let pl = name.len();
    let sl = suffix.len();
    buf[..pl].copy_from_slice(name);

    // Convert `num` to ASCII decimal digits (written from the back).
    let mut digits = [0u8; 20];
    let mut pos = 20usize;
    let mut n = num;
    if n == 0 {
        pos = 19;
        digits[19] = b'0';
    } else {
        while n > 0 {
            pos -= 1;
            digits[pos] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    let dl = 20 - pos;

    buf[pl..pl + dl].copy_from_slice(&digits[pos..]);
    buf[pl + dl..pl + dl + sl].copy_from_slice(suffix);
    pl + dl + sl
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn templated_reseeds_buffer_across_sequential_searches() {
        if !crate::keccak_avx2::is_avx2() {
            eprintln!("skipping: no AVX2");
            return;
        }
        // A single-thread pool forces both searches onto the same thread, so the
        // thread-local templated buffer (and its last digit count) survives from
        // the first search into the second. Both searches stay within 6-digit
        // numbers (100_000..1_000_000), so the second one starts at the same
        // digit count the first one ended with: without the epoch re-seed it
        // would hash the first (equal-length) name and miss every match.
        let pool =
            rayon::ThreadPoolBuilder::new().num_threads(1).build().expect("build a 1-thread pool");
        pool.install(|| {
            let matches = |name: &str, num: u64| {
                let cand = format!("{name}{num}()");
                let h = calculate_keccak_256(cand.as_bytes());
                h[0] == 0x12 && h[1] == 0x34
            };

            let a = generate_vanity_function_name(
                b"1234",
                b"transfer(address)",
                b"",
                100_000,
                Some(1_000_000),
            )
            .expect("first search finds a match");
            assert!(matches("transfer(address)", a), "first result must match its name");

            let b = generate_vanity_function_name(
                b"1234",
                b"approval(address)",
                b"",
                100_000,
                Some(1_000_000),
            )
            .expect("second search finds a match");
            assert!(
                matches("approval(address)", b),
                "second result must match its name, not the first search's stale template"
            );
        });
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

        // An empty pattern matches every candidate, so any num in the range is
        // a valid answer. `find_any` over a parallel iterator does not
        // guarantee which matching element it returns, so we only assert that
        // a solution within the range was found.
        let solution = solution.expect("empty pattern should always match");
        assert!(solution < 10, "solution {solution} out of range");
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

    #[test]
    fn test_long_input_over_136_bytes() {
        // Regression test: inputs >= 136 bytes must not panic in keccak256x2.
        // The two-way kernel only supports single-block inputs (< 136 bytes);
        // longer inputs must fall back to independent hashing.
        let long_name = "transferWithAuthorization";
        let long_params = "address,address,uint256,uint256,uint256,uint256,uint256,bytes,bytes,bytes,bytes,bytes,bytes,bytes,bytes,bytes";
        // Verify the candidate exceeds 136 bytes.
        let candidate = format!("{}12345({})", long_name, long_params);
        assert!(
            candidate.len() >= 136,
            "test requires candidate >= 136 bytes, got {}",
            candidate.len()
        );

        let hash = calculate_keccak_256(candidate.as_bytes());
        let pattern = format!("{:02x}{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2], hash[3]);

        let solution = generate_vanity_function_name(
            pattern.as_bytes(),
            long_name.as_bytes(),
            long_params.as_bytes(),
            0,
            Some(100000),
        );

        assert!(solution.is_some());
        assert_eq!(solution.unwrap(), 12345);
    }

    #[test]
    fn test_odd_range_start() {
        // Regression test: odd range_start must not leave HASH_COUNTER at 0
        // and must still find solutions correctly.
        let fn_name = "transfer";
        let fn_params = "address,uint256";
        let fn_suffix = 12346u64; // even number → will be in pair (12346, 12347)

        let full_fn = format!("{}{}({})", fn_name, fn_suffix, fn_params);
        let hash = calculate_keccak_256(full_fn.as_bytes());
        let pattern = format!("{:02x}{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2], hash[3]);

        // Start at an odd number so num1 is always odd.
        let solution = generate_vanity_function_name(
            pattern.as_bytes(),
            fn_name.as_bytes(),
            fn_params.as_bytes(),
            1, // odd start
            Some(100000),
        );

        assert!(solution.is_some());
        assert_eq!(solution.unwrap(), fn_suffix);
    }

    #[test]
    fn test_end_none() {
        // Regression test: end = None must not overflow when range_start = 0.
        // We use a very restrictive 8-char pattern so the search finds a match
        // quickly without actually scanning to u64::MAX.
        let fn_name = "test";
        let fn_params = "";
        let fn_suffix = 42u64;

        let full_fn = format!("{}{}({})", fn_name, fn_suffix, fn_params);
        let hash = calculate_keccak_256(full_fn.as_bytes());
        let pattern = format!("{:02x}{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2], hash[3]);

        let solution = generate_vanity_function_name(
            pattern.as_bytes(),
            fn_name.as_bytes(),
            fn_params.as_bytes(),
            0,
            None, // end = None → range_end = u64::MAX
        );

        assert!(solution.is_some());
        assert_eq!(solution.unwrap(), fn_suffix);
    }

    #[test]
    fn test_single_element_range() {
        // Edge case: range with exactly one element.
        let fn_name = "test";
        let fn_params = "";
        let fn_suffix = 7u64;

        let full_fn = format!("{}{}({})", fn_name, fn_suffix, fn_params);
        let hash = calculate_keccak_256(full_fn.as_bytes());
        let pattern = format!("{:02x}{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2], hash[3]);

        let solution = generate_vanity_function_name(
            pattern.as_bytes(),
            fn_name.as_bytes(),
            fn_params.as_bytes(),
            7,
            Some(8), // range [7, 8) = {7}
        );

        assert_eq!(solution, Some(7));
    }

    #[test]
    fn test_empty_range() {
        // Edge case: empty range returns None.
        let solution = generate_vanity_function_name(
            b"1234",
            b"test",
            b"",
            5,
            Some(5), // range [5, 5) = {}
        );

        assert_eq!(solution, None);
    }
}
