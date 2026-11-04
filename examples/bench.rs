//! Benchmark harness: measures end-to-end pipeline speed (buffer building +
//! hashing + pattern compare) over a fixed range, in MH/s.
//!
//! Usage: target/maxperf/examples/bench [range] [threads]
//! e.g.   target/maxperf/examples/bench 400000000 24

use std::time::Instant;

use vanity_4b::{HASH_COUNTER, generate_vanity_function_name};

fn main() {
    let mut args = std::env::args().skip(1);
    let range: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(400_000_000);
    let threads: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(24);

    rayon::ThreadPoolBuilder::new().num_threads(threads).build_global().expect("pool");

    // 8-hex-digit pattern: probability 1/2^32, so a solution is very unlikely
    // within the bench range and we measure pure search speed.
    let pattern = b"01234567";
    let name = b"doSomething";
    let params = b"address";

    let start = Instant::now();
    let _ = generate_vanity_function_name(pattern, name, params, 0, Some(range));
    let elapsed = start.elapsed().as_secs_f64();

    let hashes = HASH_COUNTER.load(std::sync::atomic::Ordering::Relaxed);
    let mhz = hashes as f64 / elapsed / 1e6;
    println!(
        "threads={threads} range={range} elapsed={elapsed:.2}s hashes={hashes} speed={mhz:.2} MH/s ({:.2} ns/hash)",
        1e9 / (hashes as f64 / elapsed)
    );
}
