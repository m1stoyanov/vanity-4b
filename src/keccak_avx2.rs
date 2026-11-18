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
use core::sync::atomic::{AtomicU64, Ordering};

/// Keccak-256 rate in bytes.
pub const RATE: usize = 136;

/// Monotonically increasing id assigned to each `TemplatedHasher`.
///
/// A thread-local candidate buffer is re-seeded from the template only when the
/// digit count changes; that alone is not enough, because the buffer (and the
/// last digit count) survive across separate `generate_vanity_function_name`
/// calls on the same thread. Storing the creating hasher's id next to the
/// buffer lets `hash_if_match` detect that the buffer was last written by a
/// *different* hasher (e.g. a previous search with a different name) and
/// re-copy the template, so a stale name is never hashed.
static TEMPLATED_EPOCH: AtomicU64 = AtomicU64::new(0);

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

    /// XOR a pre-padded single-block buffer (136 bytes, padding already applied)
    /// into the state, reading only the non-zero words: `0..=fw` plus word 16
    /// (the `0x80` domain pad). The rest of the block is zero.
    #[inline(always)]
    unsafe fn absorb_padded(&mut self, buf: *const u8, fw: usize) {
        let wp = buf.cast::<u64>();
        let mut i = 0usize;
        while i <= fw {
            let word = core::ptr::read_unaligned(wp.add(i));
            self.xor_word(i, word);
            i += 1;
        }
        if fw < 16 {
            let word = core::ptr::read_unaligned(wp.add(16));
            self.xor_word(16, word);
        }
    }

    /// XOR a single rate word into its state register/lane (see `xor_words`).
    #[inline(always)]
    unsafe fn xor_word(&mut self, idx: usize, word: u64) {
        let v = word as i64;
        match idx {
            0 => self.a00 = _mm256_xor_si256(self.a00, _mm256_set1_epi64x(v)),
            1 => self.a01 = _mm256_xor_si256(self.a01, _mm256_set_epi64x(0, 0, 0, v)),
            2 => self.a01 = _mm256_xor_si256(self.a01, _mm256_set_epi64x(0, 0, v, 0)),
            3 => self.a01 = _mm256_xor_si256(self.a01, _mm256_set_epi64x(0, v, 0, 0)),
            4 => self.a01 = _mm256_xor_si256(self.a01, _mm256_set_epi64x(v, 0, 0, 0)),
            5 => self.a20 = _mm256_xor_si256(self.a20, _mm256_set_epi64x(0, v, 0, 0)),
            6 => self.a11 = _mm256_xor_si256(self.a11, _mm256_set_epi64x(0, 0, 0, v)),
            7 => self.a31 = _mm256_xor_si256(self.a31, _mm256_set_epi64x(0, 0, v, 0)),
            8 => self.a21 = _mm256_xor_si256(self.a21, _mm256_set_epi64x(0, v, 0, 0)),
            9 => self.a41 = _mm256_xor_si256(self.a41, _mm256_set_epi64x(v, 0, 0, 0)),
            10 => self.a20 = _mm256_xor_si256(self.a20, _mm256_set_epi64x(0, 0, 0, v)),
            11 => self.a21 = _mm256_xor_si256(self.a21, _mm256_set_epi64x(0, 0, 0, v)),
            12 => self.a11 = _mm256_xor_si256(self.a11, _mm256_set_epi64x(0, 0, v, 0)),
            13 => self.a41 = _mm256_xor_si256(self.a41, _mm256_set_epi64x(0, v, 0, 0)),
            14 => self.a31 = _mm256_xor_si256(self.a31, _mm256_set_epi64x(v, 0, 0, 0)),
            15 => self.a20 = _mm256_xor_si256(self.a20, _mm256_set_epi64x(v, 0, 0, 0)),
            16 => self.a31 = _mm256_xor_si256(self.a31, _mm256_set_epi64x(0, 0, 0, v)),
            _ => {}
        }
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

/// Powers of 10 for fast decimal digit counting.
const POW10: [u64; 19] = [
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
    100_000_000_000,
    1_000_000_000_000,
    10_000_000_000_000,
    100_000_000_000_000,
    1_000_000_000_000_000,
    10_000_000_000_000_000,
    100_000_000_000_000_000,
    1_000_000_000_000_000_000,
    10_000_000_000_000_000_000,
];

/// Number of decimal digits in `n` (1..=20).
#[inline]
pub fn digit_count(n: u64) -> usize {
    let mut lo = 0usize;
    let mut hi = POW10.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if n >= POW10[mid] {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo + 1
}

/// Write the decimal digits of `num` (exactly `d` of them) into
/// `buf[name_len..name_len + d]`, most significant first.
#[inline]
pub fn write_digits(buf: &mut [u8], name_len: usize, num: u64, d: usize) {
    let end = name_len + d;
    let mut n = num;
    let mut pos = end;
    while n >= 100 {
        let p = (n % 100) as u8;
        buf[pos - 2] = b'0' + p / 10;
        buf[pos - 1] = b'0' + p % 10;
        pos -= 2;
        n /= 100;
    }
    if n >= 10 {
        buf[pos - 2] = b'0' + (n / 10) as u8;
        buf[pos - 1] = b'0' + (n % 10) as u8;
    } else {
        buf[pos - 1] = b'0' + n as u8;
    }
}

/// Pre-padded single-block Keccak templates: for each digit count `d` (1..=20),
/// a 136-byte block = `name + [d zeros] + suffix` with Keccak padding applied.
/// The digit positions are zero so [`write_digits`] can patch them in place.
pub struct SingleBlockTemplates {
    pub blocks: [[u8; 136]; 21],
    pub fw: [usize; 21],
}

impl SingleBlockTemplates {
    pub fn build(name: &[u8], suffix: &[u8]) -> Self {
        let mut blocks = [[0u8; 136]; 21];
        let mut fw = [0usize; 21];
        for d in 1..=20usize {
            let b = &mut blocks[d];
            b[..name.len()].copy_from_slice(name);
            let digits_end = name.len() + d;
            b[digits_end..digits_end + suffix.len()].copy_from_slice(suffix);
            let len = digits_end + suffix.len();
            b[len] = 0x01; // 0x01 pad (original/Ethereum)
            b[135] |= 0x80; // 0x80 domain pad
            // Word index of the `0x01` pad byte (`len`), so `absorb_padded` reads
            // through it. Using `len / 8` (not `(len - 1) / 8`) so the pad word is
            // included even when `len` is a multiple of 8.
            fw[d] = len / 8;
        }
        Self { blocks, fw }
    }
}

/// Convert a hex pattern (1..8 chars) into a `(target, mask)` u32 pair so that
/// `(prefix & mask) == target` tests the method-id prefix. The pattern's first
/// character is the high nibble of the first hash byte (the least significant
/// byte of the little-endian prefix u32).
#[inline]
pub fn pattern_to_target_mask(pattern: &[u8]) -> (u32, u32) {
    let mut target = 0u32;
    let mut mask = 0u32;
    for (i, &c) in pattern.iter().enumerate() {
        let v = crate::HEX_LOOKUP_TABLE[c as usize] as u32;
        let shift = 8 * (i / 2) + (4 - 4 * (i % 2));
        target |= v << shift;
        mask |= 0xF << shift;
    }
    (target, mask)
}

/// A templated single-block Keccak-256 hasher: precomputes the padding for
/// every digit count and patches only the digits per candidate, then checks the
/// method-id prefix before squeezing the full digest.
pub struct TemplatedHasher {
    templates: SingleBlockTemplates,
    target: u32,
    mask: u32,
    name_len: usize,
    suffix_len: usize,
    /// Id of this instance (see [`TEMPLATED_EPOCH`]).
    epoch: u64,
}

impl TemplatedHasher {
    pub fn new(name: &[u8], suffix: &[u8], pattern: &[u8]) -> Self {
        let templates = SingleBlockTemplates::build(name, suffix);
        let (target, mask) = pattern_to_target_mask(pattern);
        let epoch = TEMPLATED_EPOCH.fetch_add(1, Ordering::Relaxed);
        Self { templates, target, mask, name_len: name.len(), suffix_len: suffix.len(), epoch }
    }

    /// Id of this instance, stored alongside a thread-local buffer so a stale
    /// buffer from a previous search is re-seeded.
    #[inline]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Total candidate length for `num` (for verification slices).
    #[inline]
    pub fn len(&self, num: u64) -> usize {
        self.name_len + digit_count(num) + self.suffix_len
    }

    /// Hash `name + digits(num) + suffix`; return the full digest only if the
    /// method-id prefix matches the pattern, else `None`.
    ///
    /// `buf` and `last_d` are per-thread scratch state reused across candidates
    /// *and* across searches. `last_epoch` records which hasher last seeded the
    /// buffer; the template is re-copied when either the hasher or the digit
    /// count changed, so a buffer left over from an earlier search (different
    /// name) is never hashed.
    ///
    /// # Safety
    /// Must only be called when [`is_avx2`] is true.
    #[target_feature(enable = "avx2")]
    pub fn hash_if_match(
        &self,
        buf: &mut [u8; 136],
        last_d: &mut usize,
        last_epoch: &mut u64,
        num: u64,
    ) -> Option<[u8; 32]> {
        let d = digit_count(num);
        if *last_epoch != self.epoch || *last_d != d {
            buf.copy_from_slice(&self.templates.blocks[d]);
            *last_d = d;
            *last_epoch = self.epoch;
        }
        write_digits(buf, self.name_len, num, d);
        let mut s = unsafe { State::new() };
        unsafe {
            s.absorb_padded(buf.as_ptr(), self.templates.fw[d]);
            s.permute();
        }
        let prefix = _mm256_extract_epi64::<0>(s.a00) as u32;
        if (prefix & self.mask) == self.target { Some(unsafe { s.squeeze32() }) } else { None }
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
    fn digit_count_and_write() {
        for n in [
            0u64,
            1,
            9,
            10,
            99,
            100,
            999,
            1000,
            12345,
            99_999,
            100_000,
            999_999,
            1_000_000,
            123_456_789,
            999_999_999,
            1_000_000_000,
            12_345_678_901,
            u64::MAX,
        ] {
            let d = digit_count(n);
            assert_eq!(d, n.to_string().len(), "digit_count({n})");
            let mut buf = [0u8; 40];
            write_digits(&mut buf, 0, n, d);
            let got = std::str::from_utf8(&buf[..d]).unwrap();
            assert_eq!(got, n.to_string(), "write_digits({n})");
        }
    }

    #[test]
    fn pattern_to_target_mask_full() {
        // Full 8-char pattern: all 32 bits masked, target = method id.
        let (target, mask) = pattern_to_target_mask(b"a1b2c3d4");
        assert_eq!(mask, 0xFFFF_FFFF);
        // prefix little-endian: byte0=0xa1 (lsb) .. byte3=0xd4 (msb).
        assert_eq!(target, 0xD4C3_B2A1);
        // Partial pattern: only the first nibble of the first byte is masked.
        let (t2, m2) = pattern_to_target_mask(b"a");
        assert_eq!(m2, 0x0000_00F0);
        assert_eq!(t2, 0x0000_00A0);
        let (t3, m3) = pattern_to_target_mask(b"a1");
        assert_eq!(m3, 0x0000_00FF);
        assert_eq!(t3, 0x0000_00A1);
        let (t4, m4) = pattern_to_target_mask(b"a1b");
        assert_eq!(m4, 0x0000_F0FF);
        assert_eq!(t4, 0x0000_B0A1);
    }

    #[test]
    fn templated_matches_keccak_asm() {
        if !is_avx2() {
            eprintln!("skipping: no AVX2");
            return;
        }
        let name = b"doSomething";
        let suffix = b"(address)";
        let hasher = TemplatedHasher::new(name, suffix, b""); // empty pattern: always match
        let mut buf = [0u8; 136];
        let mut last_d = 0;
        let mut last_epoch = u64::MAX;
        for num in [
            0u64,
            1,
            9,
            10,
            99,
            100,
            999,
            1000,
            12_345,
            99_999_999,
            100_000_000,
            1_234_567_890,
            12_345_678_901_234_567_890u64,
            u64::MAX,
        ] {
            let h = unsafe { hasher.hash_if_match(&mut buf, &mut last_d, &mut last_epoch, num) }
                .expect("empty pattern must match");
            let candidate = format!("doSomething{num}(address)");
            let ref_h: [u8; 32] = keccak_asm::Keccak256::digest(candidate.as_bytes()).into();
            assert_eq!(h, ref_h, "templated mismatch num={num}");
        }
    }

    #[test]
    fn templated_prefix_match() {
        if !is_avx2() {
            eprintln!("skipping: no AVX2");
            return;
        }
        let name = b"transfer";
        let suffix = b"(address,uint256)";
        let num = 12345u64;
        let candidate = format!("transfer{num}(address,uint256)");
        let h: [u8; 32] = keccak_asm::Keccak256::digest(candidate.as_bytes()).into();
        let pattern = format!("{:02x}{:02x}{:02x}{:02x}", h[0], h[1], h[2], h[3]);
        let hasher = TemplatedHasher::new(name, suffix, pattern.as_bytes());
        let mut buf = [0u8; 136];
        let mut last_d = 0;
        let mut last_epoch = u64::MAX;
        assert!(
            unsafe { hasher.hash_if_match(&mut buf, &mut last_d, &mut last_epoch, num) }.is_some(),
            "full 8-char pattern must match its own hash"
        );
        // A one-nibble pattern must also match. This is a fresh hasher (new
        // epoch) reusing the same buffer; the epoch change must re-seed it.
        let p1 = pattern.as_bytes()[0..1].to_vec();
        let h1 = TemplatedHasher::new(name, suffix, &p1);
        assert!(unsafe { h1.hash_if_match(&mut buf, &mut last_d, &mut last_epoch, num) }.is_some());
    }

    #[test]
    fn templated_reseeds_buffer_on_hasher_change() {
        if !is_avx2() {
            eprintln!("skipping: no AVX2");
            return;
        }
        // Two hashers with different names, sharing one buffer at the same digit
        // count. The second hasher must re-seed the buffer with its own name
        // (via the epoch change), not keep the first hasher's stale template.
        // Without the epoch check the buffer would retain the first name and the
        // second hasher would hash the wrong candidate.
        let num = 12345u64; // 5 digits
        let cand_a = format!("nameA{num}(p)");
        let cand_b = format!("nameB{num}(p)");
        let ha: [u8; 32] = keccak_asm::Keccak256::digest(cand_a.as_bytes()).into();
        let hb: [u8; 32] = keccak_asm::Keccak256::digest(cand_b.as_bytes()).into();
        assert_ne!(&ha[..4], &hb[..4], "test requires the two names to differ in the hash prefix");
        // Pattern = first 4 bytes of name B's hash, so only name B can match.
        let pattern = format!("{:02x}{:02x}{:02x}{:02x}", hb[0], hb[1], hb[2], hb[3]);
        let mut buf = [0u8; 136];
        let mut last_d = 0;
        let mut last_epoch = u64::MAX;
        let hasher_a = TemplatedHasher::new(b"nameA", b"(p)", pattern.as_bytes());
        let hasher_b = TemplatedHasher::new(b"nameB", b"(p)", pattern.as_bytes());
        // Hasher A seeds the buffer with its name; its candidate does not match.
        assert!(
            unsafe { hasher_a.hash_if_match(&mut buf, &mut last_d, &mut last_epoch, num) }
                .is_none(),
            "name A must not match name B's pattern"
        );
        // Hasher B reuses the buffer at the same digit count. The epoch change
        // must re-seed it to name B, whose candidate matches.
        assert!(
            unsafe { hasher_b.hash_if_match(&mut buf, &mut last_d, &mut last_epoch, num) }
                .is_some(),
            "name B must match after the epoch re-seed (a stale buffer would fail this)"
        );
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

    #[test]
    fn templated_long_names() {
        if !is_avx2() {
            eprintln!("skipping: no AVX2");
            return;
        }
        // Long names so the 0x01 pad word lands in every rate word (fw = 8..16),
        // covering the previously mis-laned words 8, 11, 13.
        for (name, suffix) in [
            (vec![b'a'; 60], "(address)"), // len 70..89  -> fw 8..11
            (vec![b'b'; 85], "(address)"), // len 95..114 -> fw 11..14
            (vec![b'c'; 100], "(address)"), // len 110..129 -> fw 13..16
        ] {
            let hasher = TemplatedHasher::new(&name, suffix.as_bytes(), b"");
            let mut buf = [0u8; 136];
            let mut last_d = 0;
            let mut last_epoch = u64::MAX;
            for num in [
                0u64,
                1,
                9,
                10,
                99,
                100,
                999_999,
                12_345_678_901,
                999_999_999_999_999_999u64,
                u64::MAX,
            ] {
                let d = digit_count(num);
                let h = unsafe { hasher.hash_if_match(&mut buf, &mut last_d, &mut last_epoch, num) }
                    .expect("empty pattern must match");
                let candidate = format!("{}{num}{suffix}", String::from_utf8(name.clone()).unwrap());
                let ref_h: [u8; 32] = keccak_asm::Keccak256::digest(candidate.as_bytes()).into();
                assert_eq!(h, ref_h, "long-name templated mismatch d={d}");
            }
        }
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
