//! Micro-probe: isolate the pure AVX2 Keccak-f permute cost from the
//! per-candidate overhead (absorb + digit patch + prefix + squeeze).
//! Uses ~30-byte single-block messages (exactly one permutation each).
//!
//! Usage: target/maxperf/examples/perf_probe [iters]

use std::time::Instant;

use vanity_4b::keccak_avx2;

fn main() {
    let iters: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(6_000_000);

    assert!(keccak_avx2::is_avx2(), "need AVX2");

    // A realistic ~30-byte single-block candidate message (1 permutation).
    let mut data: Vec<u8> = (0u8..30).map(|i| i.wrapping_mul(7)).collect();
    data.truncate(30);

    use std::hint::black_box;

    // (a) Single candidate per iteration == 1 permute + absorb + squeeze.
    let mut acc: u64 = 0;
    let t = Instant::now();
    for _ in 0..iters {
        let h = unsafe { keccak_avx2::keccak256(black_box(&data)) };
        acc = acc.wrapping_add(h[0] as u64);
    }
    let full = t.elapsed();
    black_box(acc);

    // (b) Two candidates per iteration via the two-way kernel == 2 permutes.
    let mut data2: Vec<u8> = (0u8..30).map(|i| i.wrapping_mul(11)).collect();
    data2.truncate(30);
    let s2 = iters / 2;
    let mut acc2: u64 = 0;
    let t2 = Instant::now();
    for _ in 0..s2 {
        let (ha, hb) = unsafe { keccak_avx2::keccak256x2(black_box(&data), black_box(&data2)) };
        acc2 = acc2.wrapping_add(ha[0] as u64).wrapping_add(hb[0] as u64);
    }
    let two = t2.elapsed();
    black_box(acc2);

    let full_ns = full.as_nanos() as f64 / iters as f64;
    let two_ns = two.as_nanos() as f64 / (s2 * 2) as f64; // ns per candidate

    // (c) Reference: the keccak-asm crate's own AVX2 kernel (same CRYPTOGAMS
    //     layout). If it is meaningfully faster, our instruction sequence is not
    //     optimal.
    let mut acc3: u64 = 0;
    let t3 = Instant::now();
    for _ in 0..iters {
        let h = keccak_asm::Keccak256::digest(black_box(&data));
        acc3 = acc3.wrapping_add(h[0] as u64);
    }
    let ref_ns = t3.elapsed().as_nanos() as f64 / iters as f64;
    black_box(acc3);

    println!("single keccak256:      {:8.2} ns/candidate  ({:5.2} MH/s)", full_ns, 1e9 / full_ns);
    println!("two-way keccak256x2:   {:8.2} ns/candidate  ({:5.2} MH/s)", two_ns, 1e9 / two_ns);
    println!("keccak-asm (ref):      {:8.2} ns/candidate  ({:5.2} MH/s)", ref_ns, 1e9 / ref_ns);
    println!(
        "ours vs keccak-asm:    {:+8.2}%  ({:+.2} ns/candidate)",
        (full_ns - ref_ns) / ref_ns * 100.0,
        full_ns - ref_ns
    );
    println!(
        "two-way vs single:     {:+8.2}%  ({:+.2} ns/candidate)",
        (two_ns - full_ns) / full_ns * 100.0,
        two_ns - full_ns
    );
}
