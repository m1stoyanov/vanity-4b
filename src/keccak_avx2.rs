//! AVX2 Keccak-256 (original/Ethereum padding, `0x01 … 0x80`).
//!
//! The permutation kernel is the CRYPTOGAMS `keccak1600-avx2` (BSD-3-Clause),
//! as adapted by the `keccak-asm` crate, turned into a self-contained
//! one-shot function so it can be selected at runtime on AVX2 CPUs and
//! skipped everywhere else.
//!
//! `#[target_feature(enable = "avx2")]` keeps the rest of the crate
//! buildable (and runnable) on non-AVX2 x86-64: callers must check
//! [`is_avx2`] before invoking the `unsafe` entry points.

#![allow(unsafe_op_in_unsafe_fn)]

use core::arch::x86_64::*;

/// Keccak-256 rate in bytes.
pub const RATE: usize = 136;

const RC: [u64; 24] = [
    0x1,
    0x8082,
    0x800000000000808a,
    0x8000000080008000,
    0x808b,
    0x80000001,
    0x8000000080008081,
    0x8000000000008009,
    0x8a,
    0x88,
    0x80008009,
    0x8000000a,
    0x8000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x80000001,
    0x8000000080008008,
];

#[inline(always)]
unsafe fn mix(a: __m256i, b: __m256i, c: __m256i, d: __m256i) -> __m256i {
    // Select [a[0], b[1], c[2], d[3]] with two blend levels.
    _mm256_blend_epi32::<60>(_mm256_blend_epi32::<192>(a, d), _mm256_blend_epi32::<48>(b, c))
}

#[inline(always)]
unsafe fn chi(a: __m256i, b: __m256i, c: __m256i) -> __m256i {
    _mm256_xor_si256(a, _mm256_andnot_si256(b, c))
}

/// One Keccak-f[1600] state packed into seven YMM registers.
///
/// Lane layout (state word index per lane) matches `keccak-asm`:
/// a00=[0], a01=[1,2,3,4], a20=[10,20,5,15], a31=[16,7,23,14],
/// a21=[11,22,8,19], a41=[21,17,13,9], a11=[6,12,18,24].
struct State {
    a00: __m256i,
    a01: __m256i,
    a20: __m256i,
    a31: __m256i,
    a21: __m256i,
    a41: __m256i,
    a11: __m256i,
}

impl State {
    #[inline(always)]
    unsafe fn new() -> Self {
        core::mem::zeroed()
    }

    /// XOR a full rate block (136 bytes, no padding) into the state.
    #[inline(always)]
    unsafe fn absorb_full(&mut self, input: *const u8) {
        // Read the 17 rate words; capacity words (17..24) stay zero.
        let w = core::array::from_fn(|i| core::ptr::read_unaligned(input.add(i * 8).cast::<u64>()));
        self.xor_words(&w);
    }

    /// XOR the final partial block with Keccak padding into the state.
    /// `len` is the number of message bytes in this last block (`< RATE`).
    #[inline(always)]
    unsafe fn absorb_last(&mut self, input: *const u8, len: usize) {
        let fw = len / 8; // number of full 8-byte words
        let mut w = [0u64; 17];
        // Full words: contiguous, branch-free.
        let wptr = input.cast::<u64>();
        for (i, slot) in w.iter_mut().take(fw).enumerate() {
            *slot = core::ptr::read_unaligned(wptr.add(i));
        }
        // The word holding the `0x01` pad at byte `len` (index `fw`).
        let rem = len - fw * 8; // 0..=7 data bytes in this word
        let mut pad = 0u64;
        for b in 0..rem {
            pad |= u64::from(*input.add(fw * 8 + b)) << (b * 8);
        }
        pad |= 1u64 << (rem * 8);
        w[fw] = pad;
        // `0x80` domain pad at byte RATE-1 (word 16, high bit).
        w[16] |= 1u64 << 63;
        self.xor_words(&w);
    }

    #[inline(always)]
    unsafe fn xor_words(&mut self, w: &[u64; 17]) {
        // `_mm256_set_epi64x(e3,e2,e1,e0)` => lane0=e0, lane1=e1, lane2=e2, lane3=e3.
        // Lane layout (state word per lane): a00=[0], a01=[1,2,3,4],
        // a20=[10,20,5,15], a31=[16,7,23,14], a21=[11,22,8,19],
        // a41=[21,17,13,9], a11=[6,12,18,24]. Words >= 17 are capacity (zero).
        self.a00 = _mm256_xor_si256(self.a00, _mm256_set1_epi64x(w[0] as i64));
        self.a01 = _mm256_xor_si256(
            self.a01,
            _mm256_set_epi64x(w[4] as i64, w[3] as i64, w[2] as i64, w[1] as i64),
        );
        self.a20 = _mm256_xor_si256(
            self.a20,
            _mm256_set_epi64x(w[15] as i64, w[5] as i64, 0, w[10] as i64),
        );
        self.a31 = _mm256_xor_si256(
            self.a31,
            _mm256_set_epi64x(w[14] as i64, 0, w[7] as i64, w[16] as i64),
        );
        self.a21 = _mm256_xor_si256(self.a21, _mm256_set_epi64x(0, w[8] as i64, 0, w[11] as i64));
        self.a41 = _mm256_xor_si256(self.a41, _mm256_set_epi64x(w[9] as i64, w[13] as i64, 0, 0));
        self.a11 = _mm256_xor_si256(self.a11, _mm256_set_epi64x(0, 0, w[12] as i64, w[6] as i64));
    }

    /// Keccak-f[1600]: 24 rounds.
    #[inline(always)]
    unsafe fn permute(&mut self) {
        for &rc in &RC {
            let mut t6 = _mm256_shuffle_epi32::<78>(self.a20);
            let mut t5 = _mm256_xor_si256(self.a41, self.a31);
            let mut t2 = _mm256_xor_si256(self.a21, self.a11);
            t5 = _mm256_xor_si256(t5, self.a01);
            t5 = _mm256_xor_si256(t5, t2);
            let mut t4 = _mm256_permute4x64_epi64::<147>(t5);
            t6 = _mm256_xor_si256(t6, self.a20);
            let mut t0 = _mm256_permute4x64_epi64::<78>(t6);
            let mut t1 = _mm256_srli_epi64::<63>(t5);
            t2 = _mm256_add_epi64(t5, t5);
            t1 = _mm256_or_si256(t1, t2);
            let mut t8 = _mm256_permute4x64_epi64::<57>(t1);
            let mut t7 = _mm256_xor_si256(t1, t4);
            t7 = _mm256_permute4x64_epi64::<0>(t7);
            t6 = _mm256_xor_si256(t6, self.a00);
            t6 = _mm256_xor_si256(t6, t0);
            t0 = _mm256_srli_epi64::<63>(t6);
            t1 = _mm256_add_epi64(t6, t6);
            t1 = _mm256_or_si256(t1, t0);
            self.a20 = _mm256_xor_si256(self.a20, t7);
            self.a00 = _mm256_xor_si256(self.a00, t7);
            t8 = _mm256_blend_epi32::<192>(t8, t1);
            t4 = _mm256_blend_epi32::<3>(t4, t6);
            t8 = _mm256_xor_si256(t8, t4);
            let mut t3 = _mm256_sllv_epi64(self.a20, _mm256_set_epi64x(41, 36, 18, 3));
            self.a20 = _mm256_srlv_epi64(self.a20, _mm256_set_epi64x(23, 28, 46, 61));
            self.a20 = _mm256_or_si256(self.a20, t3);
            self.a31 = _mm256_xor_si256(self.a31, t8);
            t4 = _mm256_sllv_epi64(self.a31, _mm256_set_epi64x(39, 56, 6, 45));
            self.a31 = _mm256_srlv_epi64(self.a31, _mm256_set_epi64x(25, 8, 58, 19));
            self.a31 = _mm256_or_si256(self.a31, t4);
            self.a21 = _mm256_xor_si256(self.a21, t8);
            t5 = _mm256_sllv_epi64(self.a21, _mm256_set_epi64x(8, 55, 61, 10));
            self.a21 = _mm256_srlv_epi64(self.a21, _mm256_set_epi64x(56, 9, 3, 54));
            self.a21 = _mm256_or_si256(self.a21, t5);
            self.a41 = _mm256_xor_si256(self.a41, t8);
            t6 = _mm256_sllv_epi64(self.a41, _mm256_set_epi64x(20, 25, 15, 2));
            self.a41 = _mm256_srlv_epi64(self.a41, _mm256_set_epi64x(44, 39, 49, 62));
            self.a41 = _mm256_or_si256(self.a41, t6);
            self.a11 = _mm256_xor_si256(self.a11, t8);
            t3 = _mm256_permute4x64_epi64::<141>(self.a20);
            t4 = _mm256_permute4x64_epi64::<141>(self.a31);
            t7 = _mm256_sllv_epi64(self.a11, _mm256_set_epi64x(14, 21, 43, 44));
            t1 = _mm256_srlv_epi64(self.a11, _mm256_set_epi64x(50, 43, 21, 20));
            t1 = _mm256_or_si256(t1, t7);
            self.a01 = _mm256_xor_si256(self.a01, t8);
            t5 = _mm256_permute4x64_epi64::<27>(self.a21);
            t6 = _mm256_permute4x64_epi64::<114>(self.a41);
            t8 = _mm256_sllv_epi64(self.a01, _mm256_set_epi64x(27, 28, 62, 1));
            t2 = _mm256_srlv_epi64(self.a01, _mm256_set_epi64x(37, 36, 2, 63));
            t2 = _mm256_or_si256(t2, t8);

            self.a20 = chi(t2, mix(t4, t5, t6, t3), mix(t6, t4, t3, t5));
            self.a31 =
                _mm256_permute4x64_epi64::<27>(chi(t3, mix(t2, t6, t4, t5), mix(t4, t2, t5, t6)));
            self.a21 = chi(t4, mix(t6, t3, t5, t2), mix(t5, t6, t2, t3));
            self.a41 =
                _mm256_permute4x64_epi64::<141>(chi(t5, mix(t3, t4, t2, t6), mix(t2, t3, t6, t4)));
            self.a11 =
                _mm256_permute4x64_epi64::<114>(chi(t6, mix(t5, t2, t3, t4), mix(t3, t5, t4, t2)));
            self.a01 = chi(
                t1,
                _mm256_blend_epi32::<192>(_mm256_permute4x64_epi64::<57>(t1), self.a00),
                _mm256_blend_epi32::<48>(_mm256_permute4x64_epi64::<30>(t1), self.a00),
            );
            self.a00 = _mm256_xor_si256(
                self.a00,
                _mm256_permute4x64_epi64::<0>(_mm256_andnot_si256(t1, _mm256_srli_si256::<8>(t1))),
            );
            self.a00 = _mm256_xor_si256(self.a00, _mm256_set1_epi64x(rc as i64));
        }
    }

    /// First 32 bytes of the state (little-endian words 0..3).
    #[inline(always)]
    unsafe fn squeeze32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&(_mm256_extract_epi64::<0>(self.a00) as u64).to_le_bytes());
        out[8..16].copy_from_slice(&(_mm256_extract_epi64::<0>(self.a01) as u64).to_le_bytes());
        out[16..24].copy_from_slice(&(_mm256_extract_epi64::<1>(self.a01) as u64).to_le_bytes());
        out[24..32].copy_from_slice(&(_mm256_extract_epi64::<2>(self.a01) as u64).to_le_bytes());
        out
    }
}

/// Compute Keccak-256 of `input` using AVX2.
///
/// # Safety
/// Must only be called when [`is_avx2`] is true.
#[target_feature(enable = "avx2")]
pub unsafe fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut s = unsafe { State::new() };
    let len = input.len();
    let ptr = input.as_ptr();
    let mut off = 0usize;
    while off + RATE <= len {
        unsafe {
            s.absorb_full(ptr.add(off));
            s.permute();
        }
        off += RATE;
    }
    unsafe {
        s.absorb_last(ptr.add(off), len - off);
        s.permute();
        s.squeeze32()
    }
}

/// Compute Keccak-256 of two inputs in parallel using AVX2.
///
/// Processes two independent Keccak states with their 14 lane registers kept
/// live and the rounds interleaved, so the out-of-order engine can overlap the
/// work of both. Both inputs must be a single block (`< RATE` bytes), which is
/// the common case for vanity candidates.
///
/// # Safety
/// Must only be called when [`is_avx2`] is true.
#[target_feature(enable = "avx2")]
pub unsafe fn keccak256x2(a: &[u8], b: &[u8]) -> ([u8; 32], [u8; 32]) {
    debug_assert!(a.len() < RATE && b.len() < RATE);
    let mut sa = unsafe { State::new() };
    let mut sb = unsafe { State::new() };
    unsafe {
        sa.absorb_last(a.as_ptr(), a.len());
        sb.absorb_last(b.as_ptr(), b.len());
        sa.permute();
        sb.permute();
        (sa.squeeze32(), sb.squeeze32())
    }
}

/// True if the current CPU supports AVX2.
#[inline]
pub fn is_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_keccak_asm_all_lengths() {
        if !is_avx2() {
            eprintln!("skipping: no AVX2");
            return;
        }
        // Cover every padding boundary and several multi-block sizes.
        for len in 0..=300usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let ref_out: [u8; 32] = keccak_asm::Keccak256::digest(&data).into();
            let avx2_out = unsafe { keccak256(&data) };
            assert_eq!(
                avx2_out,
                ref_out,
                "mismatch at len={len}: avx2={} ref={}",
                hex_str(&avx2_out),
                hex_str(&ref_out)
            );
        }
    }

    #[test]
    fn two_way_matches_keccak_asm() {
        if !is_avx2() {
            eprintln!("skipping: no AVX2");
            return;
        }
        // Both inputs single-block; verify each lane independently.
        for (la, lb) in [(0, 0), (1, 31), (135, 134), (29, 58), (8, 0), (133, 7)] {
            let da: Vec<u8> = (0..la).map(|i| (i * 3 + 1) as u8).collect();
            let db: Vec<u8> = (0..lb).map(|i| (i * 5 + 2) as u8).collect();
            let (oa, ob) = unsafe { keccak256x2(&da, &db) };
            let ra: [u8; 32] = keccak_asm::Keccak256::digest(&da).into();
            let rb: [u8; 32] = keccak_asm::Keccak256::digest(&db).into();
            assert_eq!(oa, ra, "lane A mismatch la={la}");
            assert_eq!(ob, rb, "lane B mismatch lb={lb}");
        }
    }

    #[test]
    fn known_vectors() {
        if !is_avx2() {
            return;
        }
        // Keccak-256 (original) of the empty string.
        assert_eq!(
            unsafe { keccak256(b"") },
            hex_to_bytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
        // Keccak-256 of "abc".
        assert_eq!(
            unsafe { keccak256(b"abc") },
            hex_to_bytes("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        );
    }

    fn hex_to_bytes(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn hex_str(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
