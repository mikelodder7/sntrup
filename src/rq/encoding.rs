use super::modq;
use crate::params::SntrupParameters;
use zeroize::Zeroize;

/// Maximum number of pairing levels across all parameter sets (P up to 1277).
/// Levels: 1277 -> 639 -> 320 -> 160 -> 80 -> 40 -> 20 -> 10 -> 5 -> 3 -> 2 -> base case (n=1).
const fn compute_levels(p: usize) -> usize {
    let mut n = p;
    let mut levels = 0;
    while n > 1 {
        levels += 1;
        n = n.div_ceil(2);
    }
    levels
}

/// Total moduli storage across all levels (including the base case modulus).
const fn compute_m_storage(p: usize) -> usize {
    let mut n = p;
    let mut total = 0;
    while n > 1 {
        total += n;
        n = n.div_ceil(2);
    }
    total + 1 // +1 for base case modulus
}

const MAX_LEVELS: usize = compute_levels(1277); // 11
const MAX_M_STORAGE: usize = compute_m_storage(1277); // 2557

/// Constant-time divmod: *quotient = x / m, returns x % m.
/// m must be > 0 and < 16384. Matches PQClean's two-step Barrett reduction.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn uint32_divmod_uint14(quotient: &mut u32, x: u32, m: u16) -> u16 {
    let m32 = m as u32;
    let v = (0x80000000u32 as u64) / (m32 as u64);
    // First Barrett step
    let mut qpart = ((x as u64 * v) >> 31) as u32;
    let mut r = x - qpart * m32;
    *quotient = qpart;
    // Second Barrett step on remainder
    qpart = ((r as u64 * v) >> 31) as u32;
    r -= qpart * m32;
    *quotient += qpart;
    // Final speculative correction
    r = r.wrapping_sub(m32);
    *quotient += 1;
    let mask = (r >> 31).wrapping_neg(); // 0xFFFFFFFF if r underflowed (was < m), else 0
    r = r.wrapping_add(mask & m32);
    *quotient = quotient.wrapping_add(mask); // subtract 1 if we over-corrected
    r as u16
}

#[inline(always)]
fn uint32_mod_uint14(x: u32, m: u16) -> u16 {
    let mut q = 0u32;
    uint32_divmod_uint14(&mut q, x, m)
}

/// Iterative variable-radix encoding. Pairs values, emits bottom bytes when the
/// combined modulus reaches 16384, then repeats on the paired values.
/// `r` and `m` are modified in place across levels.
#[allow(clippy::cast_possible_truncation)]
fn encode(out: &mut [u8], r: &mut [u16], m: &mut [u16], n_start: usize) -> usize {
    if n_start == 0 {
        return 0;
    }
    if n_start == 1 {
        return encode_single(out, r[0] as u32, m[0] as u32);
    }

    let mut n = n_start;
    let mut pos = 0;

    while n > 1 {
        let n2 = n.div_ceil(2);
        // In-place pairing: read from [2*i, 2*i+1], write to [i].
        // Safe because i < 2*i for i >= 1, so reads precede writes.
        for i in 0..n2 {
            if 2 * i + 1 < n {
                let mut combined = r[2 * i] as u32 + (r[2 * i + 1] as u32) * (m[2 * i] as u32);
                let mut cm = (m[2 * i] as u32) * (m[2 * i + 1] as u32);
                while cm >= 16384 {
                    out[pos] = combined as u8;
                    pos += 1;
                    combined >>= 8;
                    cm = (cm + 255) >> 8;
                }
                r[i] = combined as u16;
                m[i] = cm as u16;
            } else {
                r[i] = r[2 * i];
                m[i] = m[2 * i];
            }
        }
        n = n2;
    }

    // Base case: single remaining value
    pos + encode_single(&mut out[pos..], r[0] as u32, m[0] as u32)
}

#[allow(clippy::cast_possible_truncation)]
fn encode_single(out: &mut [u8], mut val: u32, mut modulus: u32) -> usize {
    let mut pos = 0;
    while modulus > 1 {
        out[pos] = val as u8;
        pos += 1;
        val >>= 8;
        modulus = (modulus + 255) >> 8;
    }
    pos
}

/// AVX2 expansion of one decode level whose pairs all share a modulus `m` and
/// bottom-byte count `bb` — the shape levels 0-2 always have (see RESULTS.md).
///
/// Handles pairs `[lo, hi)` backward in blocks of eight 32-bit lanes:
/// `combined = out[i]·256^bb + LE(s[start + i·bb ..][..bb])`, then
/// `out[2i] = combined mod m`, `out[2i+1] = (combined / m) mod m`, replicating
/// `uint32_divmod_uint14`'s two Barrett steps plus speculative correction
/// lanewise. Callers guarantee `lo >= 8`, so a block's writes (`out[2i..2i+16]`)
/// never overlap its reads (`out[i..i+8]`).
///
/// `bb` is 1 or 2 for every level this is invoked on; other values fall back to
/// the scalar path.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
#[allow(unsafe_code)]
unsafe fn decode_level_avx2(
    out: &mut [u16],
    s: &[u8],
    m: u16,
    bb: usize,
    start: usize,
    lo: usize,
    hi: usize,
) {
    unsafe {
        use core::arch::x86_64::*;

        let m32 = u32::from(m);
        #[allow(clippy::cast_possible_truncation)]
        let v = (0x8000_0000u64 / u64::from(m32)) as u32;
        let mv = _mm256_set1_epi32(m32.cast_signed());
        let vv = _mm256_set1_epi64x(i64::from(v));

        // 8-lane u32 multiply-high-by-v, keeping bit 31 upward (the scalar
        // code's `(x as u64 * v) >> 31`). AVX2 only multiplies even 32-bit
        // lanes, so run the even and odd halves separately and reblend.
        let qhat = |x: __m256i| -> __m256i {
            let pe = _mm256_srli_epi64::<31>(_mm256_mul_epu32(x, vv));
            let po = _mm256_srli_epi64::<31>(_mm256_mul_epu32(_mm256_srli_epi64::<32>(x), vv));
            _mm256_blend_epi32::<0b1010_1010>(pe, _mm256_slli_epi64::<32>(po))
        };

        // One Barrett step: returns (quotient_part, remainder).
        let step = |x: __m256i| -> (__m256i, __m256i) {
            let q = qhat(x);
            (q, _mm256_sub_epi32(x, _mm256_mullo_epi32(q, mv)))
        };

        let mut i = hi;
        while i >= lo + 8 {
            i -= 8;

            let ov = _mm256_cvtepu16_epi32(_mm_loadu_si128(out.as_ptr().add(i) as *const __m128i));
            let bytes = if bb == 1 {
                _mm256_cvtepu8_epi32(_mm_loadl_epi64(s.as_ptr().add(start + i) as *const __m128i))
            } else {
                _mm256_cvtepu16_epi32(_mm_loadu_si128(
                    s.as_ptr().add(start + 2 * i) as *const __m128i
                ))
            };
            let shift = if bb == 1 { 8 } else { 16 };
            let combined = _mm256_add_epi32(_mm256_sllv_epi32(ov, _mm256_set1_epi32(shift)), bytes);

            // divmod: two Barrett steps then the speculative correction.
            let (q0, r0) = step(combined);
            let (q1, r1) = step(r0);
            let q = _mm256_add_epi32(q0, q1);
            let rsub = _mm256_sub_epi32(r1, mv);
            let mask = _mm256_srai_epi32::<31>(rsub);
            let rem = _mm256_add_epi32(rsub, _mm256_and_si256(mask, mv));
            let quo = _mm256_add_epi32(_mm256_add_epi32(q, _mm256_set1_epi32(1)), mask);

            // out[2i+1] = quo mod m (one more reduction; quo < m^2 / ... but a
            // single Barrett step plus correction suffices, matching
            // uint32_mod_uint14).
            let (_, hr0) = step(quo);
            let (_, hr1) = step(hr0);
            let hsub = _mm256_sub_epi32(hr1, mv);
            let hmask = _mm256_srai_epi32::<31>(hsub);
            let hi_val = _mm256_add_epi32(hsub, _mm256_and_si256(hmask, mv));

            // Interleave (rem, hi_val) into out[2i .. 2i+16] as u16.
            let lo16 = _mm256_packus_epi32(rem, hi_val); // lanes: r0..3 h0..3 r4..7 h4..7
            let fixed = _mm256_permute4x64_epi64::<0b11_01_10_00>(lo16); // r0..3 r4..7 h0..3 h4..7
            let r16 = _mm256_castsi256_si128(fixed);
            let h16 = _mm256_extracti128_si256::<1>(fixed);
            _mm_storeu_si128(
                out.as_mut_ptr().add(2 * i) as *mut __m128i,
                _mm_unpacklo_epi16(r16, h16),
            );
            _mm_storeu_si128(
                out.as_mut_ptr().add(2 * i + 8) as *mut __m128i,
                _mm_unpackhi_epi16(r16, h16),
            );
        }
    }
}

/// Iterative variable-radix decoding. Forward pass computes moduli and byte
/// offsets at each level; backward pass expands decoded values from base case.
#[allow(clippy::cast_possible_truncation)]
fn decode(out: &mut [u16], s: &[u8], m_in: &[u16], n_start: usize) {
    if n_start == 0 {
        return;
    }
    if n_start == 1 {
        decode_single(out, s, m_in[0]);
        return;
    }

    // --- Forward pass: compute level sizes, moduli, and bottom-byte totals ---

    let mut ns = [0usize; MAX_LEVELS];
    let mut num_levels = 0;
    {
        let mut n = n_start;
        while n > 1 {
            ns[num_levels] = n;
            num_levels += 1;
            n = n.div_ceil(2);
        }
    }

    // Flat storage for moduli at every level (including paired output for base case)
    let mut all_m = [0u16; MAX_M_STORAGE];
    let mut level_m_offset = [0usize; MAX_LEVELS + 1];
    let mut level_bottom_total = [0usize; MAX_LEVELS];

    // Level 0 input moduli
    all_m[..n_start].copy_from_slice(&m_in[..n_start]);
    level_m_offset[0] = 0;
    let mut m_pos = n_start;

    for level in 0..num_levels {
        let n = ns[level];
        let n2 = n.div_ceil(2);
        let m_off = level_m_offset[level];
        level_m_offset[level + 1] = m_pos;
        let mut total_bottom = 0usize;

        for i in 0..n2 {
            if 2 * i + 1 < n {
                let mut cm = (all_m[m_off + 2 * i] as u32) * (all_m[m_off + 2 * i + 1] as u32);
                let mut bb = 0usize;
                while cm >= 16384 {
                    bb += 1;
                    cm = (cm + 255) >> 8;
                }
                total_bottom += bb;
                all_m[m_pos] = cm as u16;
            } else {
                all_m[m_pos] = all_m[m_off + 2 * i];
            }
            m_pos += 1;
        }

        level_bottom_total[level] = total_bottom;
    }

    // Cumulative bottom-byte start positions
    let mut level_bottom_start = [0usize; MAX_LEVELS];
    let mut cum_bottom = 0usize;
    for level in 0..num_levels {
        level_bottom_start[level] = cum_bottom;
        cum_bottom += level_bottom_total[level];
    }

    // --- Decode base case (n = 1) ---
    let base_m_off = level_m_offset[num_levels];
    decode_single(out, &s[cum_bottom..], all_m[base_m_off]);

    // --- Backward pass: expand decoded values level by level ---
    for level in (0..num_levels).rev() {
        let n = ns[level];
        let n2 = n.div_ceil(2);
        let m_off = level_m_offset[level];

        // out[0..n2] holds decoded values; expand in-place to out[0..n].
        // Process backwards: reads from out[i], writes to out[2*i] / out[2*i+1].
        let mut bpos = level_bottom_start[level] + level_bottom_total[level];

        // Uniform-modulus fast path: when every full pair on this level shares
        // one modulus and one bottom-byte count (true for the wide levels of
        // every parameter set), `bpos` is the closed form `start + i*bb` and the
        // whole level vectorizes. Pairs below index 8 stay scalar because their
        // writes would overlap the block's reads.
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        let mut simd_done_to = n2;
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        {
            let n_full = n / 2;
            if n_full >= 16 && crate::cpu::has_avx2() {
                let m0 = all_m[m_off];
                let mut cm = u32::from(m0) * u32::from(all_m[m_off + 1]);
                let mut bb = 0usize;
                while cm >= 16384 {
                    bb += 1;
                    cm = (cm + 255) >> 8;
                }
                let uniform = (0..n_full)
                    .all(|k| all_m[m_off + 2 * k] == m0 && all_m[m_off + 2 * k + 1] == m0);
                if uniform && (bb == 1 || bb == 2) {
                    let start = level_bottom_start[level];
                    // The unpaired tail element is the highest index the scalar
                    // loop would visit, so it must be copied BEFORE the kernel
                    // runs — the kernel's stores reach out[2*n_full - 1] and
                    // would otherwise clobber out[n2 - 1] before it is read.
                    if n % 2 == 1 {
                        out[2 * (n2 - 1)] = out[n2 - 1];
                    }
                    // SAFETY: AVX2 confirmed by has_avx2(); lo = 8 keeps every
                    // block's writes clear of its reads.
                    unsafe {
                        decode_level_avx2(out, s, m0, bb, start, 8, n_full);
                    }
                    // Blocks covered [8 + ((n_full - 8) % 8), n_full).
                    simd_done_to = 8 + (n_full - 8) % 8;
                    bpos = level_bottom_start[level] + simd_done_to * bb;
                }
            }
        }
        #[cfg(not(all(target_arch = "x86_64", not(feature = "force-scalar"))))]
        let simd_done_to = n2;

        for i in (0..simd_done_to).rev() {
            if 2 * i + 1 < n {
                // Recompute bottom-byte count for this pair
                let mut cm = (all_m[m_off + 2 * i] as u32) * (all_m[m_off + 2 * i + 1] as u32);
                let mut bb = 0usize;
                while cm >= 16384 {
                    bb += 1;
                    cm = (cm + 255) >> 8;
                }

                bpos -= bb;
                let mut combined = out[i] as u32;
                for j in (0..bb).rev() {
                    combined = (combined << 8) | (s[bpos + j] as u32);
                }

                let mut q = 0u32;
                let remainder = uint32_divmod_uint14(&mut q, combined, all_m[m_off + 2 * i]);
                out[2 * i] = remainder;
                out[2 * i + 1] = uint32_mod_uint14(q, all_m[m_off + 2 * i + 1]);
            } else {
                out[2 * i] = out[i];
            }
        }
    }
}

fn decode_single(out: &mut [u16], s: &[u8], m: u16) {
    if m == 1 {
        out[0] = 0;
    } else if m <= 256 {
        out[0] = uint32_mod_uint14(s[0] as u32, m);
    } else {
        out[0] = uint32_mod_uint14(s[0] as u32 + ((s[1] as u32) << 8), m);
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rq_encode(f: &[i16], params: &SntrupParameters) -> Vec<u8> {
    let p = params.p;
    let q12 = params.q12;
    let q_u16 = params.q as u16;

    let mut r = vec![0u16; p];
    for (ri, &fi) in r.iter_mut().zip(f.iter()) {
        *ri = (fi as i32 + q12) as u16;
    }
    let mut m = vec![q_u16; p];
    let mut out = vec![0u8; params.pk_size];
    encode(&mut out, &mut r, &mut m, p);
    out
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rq_decode(c: &[u8], params: &SntrupParameters) -> Vec<i16> {
    let p = params.p;
    let q12 = params.q12;
    let q_u16 = params.q as u16;
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;

    let m = vec![q_u16; p];
    let mut r = vec![0u16; p];
    // Callers pass exactly `pk_size` bytes, so borrow directly on the hot path.
    // Only allocate-and-pad if the input is short (defensive; never happens via
    // the public API, where `EncapsulationKey::try_from` enforces the size).
    let mut padded;
    let s: &[u8] = if c.len() >= params.pk_size {
        &c[..params.pk_size]
    } else {
        padded = vec![0u8; params.pk_size];
        padded[..c.len()].copy_from_slice(c);
        &padded
    };
    decode(&mut r, s, &m, p);
    let mut f = vec![0i16; p];
    for (fi, &ri) in f.iter_mut().zip(r.iter()) {
        *fi = modq::freeze(ri as i32 - q12, q, b1, b2);
    }
    f
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rounded_encode(f: &[i16], params: &SntrupParameters) -> Vec<u8> {
    let p = params.p;
    let q12 = params.q12;
    let q_rounded = (params.q as u16).div_ceil(3);

    let mut r = vec![0u16; p];
    for (ri, &fi) in r.iter_mut().zip(f.iter()) {
        *ri = (((fi as i32 + q12) * 10923) >> 15) as u16;
    }
    let mut m = vec![q_rounded; p];
    let mut out = vec![0u8; params.rounded_encode_size];
    encode(&mut out, &mut r, &mut m, p);
    // On the decapsulation path `f` is the re-encrypted candidate, secret until (and unless)
    // the constant-time ciphertext comparison succeeds — wipe the working representation,
    // which `encode` mutates in place across pairing levels. `m` holds only public moduli.
    r.zeroize();
    out
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rounded_decode(c: &[u8], params: &SntrupParameters) -> Vec<i16> {
    let p = params.p;
    let q12 = params.q12;
    let q_rounded = (params.q as u16).div_ceil(3);
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;

    let m = vec![q_rounded; p];
    let mut r = vec![0u16; p];
    // Callers pass exactly `rounded_encode_size` bytes, so borrow directly on the
    // hot path. Only allocate-and-pad if the input is short (defensive; never
    // happens via the public API, where `Ciphertext::try_from` enforces the size).
    let mut padded;
    let s: &[u8] = if c.len() >= params.rounded_encode_size {
        &c[..params.rounded_encode_size]
    } else {
        padded = vec![0u8; params.rounded_encode_size];
        padded[..c.len()].copy_from_slice(c);
        &padded
    };
    decode(&mut r, s, &m, p);
    let mut f = vec![0i16; p];
    for (fi, &ri) in f.iter_mut().zip(r.iter()) {
        *fi = modq::freeze(ri as i32 * 3 - q12, q, b1, b2);
    }
    f
}
