use std::time::Instant;

use rayon::ThreadPoolBuilder;
use vanity_4b::{calculate_keccak_256, generate_vanity_function_name};

#[test]
#[ignore]
// Can be run with: -- --include-ignored
// Show output: -- --nocapture
fn benchmark_hash_performance() {
    // Single core performance test
    use std::time::Instant;

    let iterations = 5_000_000;
    let start = Instant::now();

    for i in 0..iterations {
        let input = format!("test{}()", i);
        let _hash = calculate_keccak_256(input.as_bytes());
    }

    let elapsed = start.elapsed();
    let hashes_per_second = iterations as f64 / elapsed.as_secs_f64();

    println!("Hash performance: {:.2} MH/s", hashes_per_second / 1_000_000.0);

    // Ensure performance is above a minimum threshold (adjust based on your hardware)
    assert!(hashes_per_second > 1_000_000.0, "You should buy a new PC"); // At least 1M hashes per second
}

#[test]
#[ignore]
// Can be run with: -- --include-ignored
// Show output: -- --nocapture
fn test_thread_scaling() {
    // Test with different thread counts
    let thread_counts = [1, 2, 4, 8, 16, 32, 64, 128];
    let pattern = b"12345678"; // Use a simpler pattern for faster testing
    let fn_name = b"doSomething";
    let fn_params = b"address";

    // Use fixed range for consistent comparison
    let range_start = 525_000_000;
    let range_end = 535_000_000; // Reduce range for faster testing

    println!(
        "Running thread scaling benchmark with pattern: 0x{}",
        std::str::from_utf8(pattern).unwrap()
    );
    println!("Using fixed range: [{},{}]", range_start, range_end);
    println!(
        "{:<10} | {:<15} | {:<10} | {:<40} | {:<20}",
        "Threads", "Time (ms)", "Speedup", "Fn Name", "Fn Signature"
    );
    println!("{:-<99}", "");

    // Base time with 1 thread (measured outside the loop to ensure consistent baseline)
    let base_time_result = run_with_threads(1, pattern, fn_name, fn_params, range_start, range_end);
    println!(
        "{:<10} | {:<15.2} | {:<10.2} | {:<40} | {:<15}",
        1,
        base_time_result.0.as_millis(),
        1.0,
        base_time_result.1,
        base_time_result.2
    );

    // Test with other thread counts
    for &threads in &thread_counts[1..] {
        let result = run_with_threads(threads, pattern, fn_name, fn_params, range_start, range_end);
        let speedup = base_time_result.0.as_secs_f64() / result.0.as_secs_f64();

        println!(
            "{:<10} | {:<15.2} | {:<10.2} | {:<40} | {:<15}",
            threads,
            result.0.as_millis(),
            speedup,
            result.1,
            result.2
        );
    }
}

// Helper function to run the test with a specific thread count
fn run_with_threads(
    threads: usize,
    pattern: &[u8],
    fn_name: &[u8],
    fn_params: &[u8],
    range_start: u64,
    range_end: u64,
) -> (std::time::Duration, String, String) {
    // Build a thread pool with the specified number of threads
    let pool =
        ThreadPoolBuilder::new().num_threads(threads).build().expect("Failed to build thread pool");

    let start = Instant::now();

    // Use the pool to run the task
    let solution = pool.install(|| {
        generate_vanity_function_name(pattern, fn_name, fn_params, range_start, Some(range_end))
    });

    let elapsed = start.elapsed();

    let mut full_name: String = "X".to_string();
    let mut signature: String = "X".to_string();

    // Log if a solution was found (useful for debugging)
    if let Some(idx) = solution {
        full_name = format!(
            "{}{}({})",
            std::str::from_utf8(fn_name).unwrap(),
            idx,
            std::str::from_utf8(fn_params).unwrap()
        );
        let hash = calculate_keccak_256(full_name.as_bytes());
        signature = format!("0x{:02x}{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2], hash[3]);
    }

    (elapsed, full_name, signature)
}
