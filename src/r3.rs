pub mod mod3;
mod vector;

use crate::ct::{smaller_mask, swap_int};
use zeroize::Zeroize;

#[allow(clippy::cast_possible_wrap)]
pub fn reciprocal(s: &[i8], p: usize) -> (isize, Vec<i8>) {
    let loops = 2 * p + 1;
    let mut r = vec![0i8; p];
    let mut f = vec![0i8; p + 1];
    f[0] = -1;
    f[1] = -1;
    f[p] = 1;

    let mut g = vec![0i8; p + 1];
    g[..p].copy_from_slice(&s[..p]);
    let mut d = p as isize;
    let mut e = p as isize;
    let mut u = vec![0i8; loops + 1];
    let mut v = vec![0i8; loops + 1];
    v[0] = 1;

    for _ in 0..loops {
        let c = mod3::quotient(g[p], f[p]);
        vector::minus_product_shift(&mut g, p + 1, &f, c);
        vector::minus_product_shift(&mut v, loops + 1, &u, c);
        e -= 1;
        let m = smaller_mask(e, d) & mod3::mask_set(g[p]);
        let (e_tmp, d_tmp) = swap_int(e, d, m);
        e = e_tmp;
        d = d_tmp;
        vector::swap(&mut f, &mut g, p + 1, m);
        vector::swap(&mut u, &mut v, loops + 1, m);
    }

    vector::product(&mut r, p, &u[p..], mod3::reciprocal(f[p]));
    // The Euclidean state is derived from the secret input — wipe it before returning.
    f.zeroize();
    g.zeroize();
    u.zeroize();
    v.zeroize();
    (smaller_mask(0, d), r)
}

#[allow(unsafe_code)]
pub fn mult(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return mult_avx2(h, f, g, p);
        }
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return mult_neon(h, f, g, p);
    }
    #[allow(unreachable_code)]
    mult_scalar(h, f, g, p);
}

fn mult_scalar(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
    let mut fg = vec![0i8; p * 2 - 1];
    for i in 0..p {
        let mut r = 0i32;
        for j in 0..=i {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = mod3::freeze(r);
    }
    for i in p..(p * 2 - 1) {
        let mut r = 0i32;
        for j in (i - p + 1)..p {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = mod3::freeze(r);
    }
    for i in (p..(p * 2) - 1).rev() {
        fg[i - p] = mod3::freeze(fg[i - p] as i32 + fg[i] as i32);
        fg[i - p + 1] = mod3::freeze(fg[i - p + 1] as i32 + fg[i] as i32);
    }
    h[..p].copy_from_slice(&fg[..p]);
    // At least one operand is secret at every call site — wipe the product scratch.
    fg.zeroize();
}

/// Row-major schoolbook multiplication with AVX2 for R3 polynomials.
///
/// Same structure as `rq::mult`'s AVX2 kernel (see its doc comment): contiguous dot products
/// over widened copies of `f` and a reversed `g`, four independent `_mm256_madd_epi16`
/// accumulators (16 multiply-accumulates per instruction), one write per output coefficient,
/// and a single mod-3 freeze per output during the `x^p ≡ x + 1` fold (|folded sum| ≤ 3p,
/// well inside `mod3::freeze`'s i32 domain).
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop
)]
unsafe fn mult_avx2(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
    unsafe {
        use core::arch::x86_64::*;

        let fg_len = p * 2 - 1;

        let mut f16 = vec![0i16; p];
        let mut g_rev = vec![0i16; p];
        for i in 0..p {
            f16[i] = f[i] as i16;
            g_rev[i] = g[p - 1 - i] as i16;
        }

        // Raw i16 row sums (|sum| ≤ p ≤ 1277), padded with one zero so the fold below may
        // read `fg[k + p]` unconditionally at `k = p - 1`.
        let mut fg = vec![0i16; fg_len + 1];
        for (i, out) in fg[..fg_len].iter_mut().enumerate() {
            let jlo = i.saturating_sub(p - 1);
            let len = i.min(p - 1) - jlo + 1;
            let fp = f16.as_ptr().add(jlo);
            let gp = g_rev.as_ptr().add(p - 1 + jlo - i);

            let mut acc0 = _mm256_setzero_si256();
            let mut acc1 = _mm256_setzero_si256();
            let mut acc2 = _mm256_setzero_si256();
            let mut acc3 = _mm256_setzero_si256();
            let mut k = 0usize;
            while k + 64 <= len {
                acc0 = _mm256_add_epi32(
                    acc0,
                    _mm256_madd_epi16(
                        _mm256_loadu_si256(fp.add(k) as *const __m256i),
                        _mm256_loadu_si256(gp.add(k) as *const __m256i),
                    ),
                );
                acc1 = _mm256_add_epi32(
                    acc1,
                    _mm256_madd_epi16(
                        _mm256_loadu_si256(fp.add(k + 16) as *const __m256i),
                        _mm256_loadu_si256(gp.add(k + 16) as *const __m256i),
                    ),
                );
                acc2 = _mm256_add_epi32(
                    acc2,
                    _mm256_madd_epi16(
                        _mm256_loadu_si256(fp.add(k + 32) as *const __m256i),
                        _mm256_loadu_si256(gp.add(k + 32) as *const __m256i),
                    ),
                );
                acc3 = _mm256_add_epi32(
                    acc3,
                    _mm256_madd_epi16(
                        _mm256_loadu_si256(fp.add(k + 48) as *const __m256i),
                        _mm256_loadu_si256(gp.add(k + 48) as *const __m256i),
                    ),
                );
                k += 64;
            }
            while k + 16 <= len {
                acc0 = _mm256_add_epi32(
                    acc0,
                    _mm256_madd_epi16(
                        _mm256_loadu_si256(fp.add(k) as *const __m256i),
                        _mm256_loadu_si256(gp.add(k) as *const __m256i),
                    ),
                );
                k += 16;
            }
            let s = _mm256_add_epi32(_mm256_add_epi32(acc0, acc1), _mm256_add_epi32(acc2, acc3));
            let s4 = _mm_add_epi32(_mm256_castsi256_si128(s), _mm256_extracti128_si256(s, 1));
            let s2 = _mm_add_epi32(s4, _mm_shuffle_epi32(s4, 0b0000_1110));
            let s1 = _mm_add_epi32(s2, _mm_shuffle_epi32(s2, 0b0000_0001));
            let mut sum = _mm_cvtsi128_si32(s1);
            while k < len {
                sum += *fp.add(k) as i32 * *gp.add(k) as i32;
                k += 1;
            }
            *out = sum as i16;
        }

        // Fold x^p ≡ x + 1 with a single mod-3 freeze per output coefficient: fg[i] (i ≥ p)
        // contributes to outputs i-p and i-p+1, and no fold target is itself ≥ p, so every
        // output is independent.
        h[0] = mod3::freeze(i32::from(fg[0]) + i32::from(fg[p]));
        for k in 1..p {
            h[k] = mod3::freeze(i32::from(fg[k]) + i32::from(fg[k + p]) + i32::from(fg[k + p - 1]));
        }

        // At least one operand is secret at every call site — wipe the widened copies and
        // the product scratch.
        f16.zeroize();
        g_rev.zeroize();
        fg.zeroize();
    }
}

/// Row-major schoolbook multiplication with NEON for R3 polynomials.
///
/// Same structure as `rq::mult`'s NEON kernel (see its doc comment for the reasoning): each
/// output coefficient's convolution sum is a contiguous dot product over `f` and a pre-reversed
/// `g`, held across EIGHT independent widening accumulators so the multiply-accumulate
/// latency is hidden, and written to memory once. Here the operands are ternary i8, so
/// `vmlal_s8`/`vmlal_high_s8` (i8×i8→i16, 8 lanes per instruction) process 64 elements per
/// unrolled iteration, and the i16 accumulator lanes stay far from overflow (each lane absorbs
/// at most `p/8` unit products; the final cross-lane sum is bounded by `p ≤ 1277`).
///
/// The `x^p ≡ x + 1` fold then adds three raw row sums (|sum| ≤ 3p = 3831, well inside
/// `mod3::freeze`'s i32 domain) with a single freeze per output coefficient, instead of the
/// reference's three.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop
)]
unsafe fn mult_neon(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
    unsafe {
        use core::arch::aarch64::*;

        let fg_len = p * 2 - 1;

        let mut g_rev = vec![0i8; p];
        for i in 0..p {
            g_rev[i] = g[p - 1 - i];
        }

        // Raw i16 row sums, padded with one zero so the fold below may read `fg[k + p]`
        // unconditionally at `k = p - 1`.
        let mut fg = vec![0i16; fg_len + 1];
        for (i, out) in fg[..fg_len].iter_mut().enumerate() {
            let jlo = i.saturating_sub(p - 1);
            let len = i.min(p - 1) - jlo + 1;
            let fp = f.as_ptr().add(jlo);
            let gp = g_rev.as_ptr().add(p - 1 + jlo - i);

            let mut acc0 = vdupq_n_s16(0);
            let mut acc1 = vdupq_n_s16(0);
            let mut acc2 = vdupq_n_s16(0);
            let mut acc3 = vdupq_n_s16(0);
            let mut acc4 = vdupq_n_s16(0);
            let mut acc5 = vdupq_n_s16(0);
            let mut acc6 = vdupq_n_s16(0);
            let mut acc7 = vdupq_n_s16(0);
            let mut k = 0usize;
            while k + 64 <= len {
                let f0 = vld1q_s8(fp.add(k));
                let f1 = vld1q_s8(fp.add(k + 16));
                let f2 = vld1q_s8(fp.add(k + 32));
                let f3 = vld1q_s8(fp.add(k + 48));
                let g0 = vld1q_s8(gp.add(k));
                let g1 = vld1q_s8(gp.add(k + 16));
                let g2 = vld1q_s8(gp.add(k + 32));
                let g3 = vld1q_s8(gp.add(k + 48));
                acc0 = vmlal_s8(acc0, vget_low_s8(f0), vget_low_s8(g0));
                acc1 = vmlal_high_s8(acc1, f0, g0);
                acc2 = vmlal_s8(acc2, vget_low_s8(f1), vget_low_s8(g1));
                acc3 = vmlal_high_s8(acc3, f1, g1);
                acc4 = vmlal_s8(acc4, vget_low_s8(f2), vget_low_s8(g2));
                acc5 = vmlal_high_s8(acc5, f2, g2);
                acc6 = vmlal_s8(acc6, vget_low_s8(f3), vget_low_s8(g3));
                acc7 = vmlal_high_s8(acc7, f3, g3);
                k += 64;
            }
            while k + 16 <= len {
                let f0 = vld1q_s8(fp.add(k));
                let g0 = vld1q_s8(gp.add(k));
                acc0 = vmlal_s8(acc0, vget_low_s8(f0), vget_low_s8(g0));
                acc1 = vmlal_high_s8(acc1, f0, g0);
                k += 16;
            }
            let total = vaddq_s16(
                vaddq_s16(vaddq_s16(acc0, acc1), vaddq_s16(acc2, acc3)),
                vaddq_s16(vaddq_s16(acc4, acc5), vaddq_s16(acc6, acc7)),
            );
            let mut sum = i32::from(vaddvq_s16(total));
            while k < len {
                sum += i32::from(*fp.add(k)) * i32::from(*gp.add(k));
                k += 1;
            }
            *out = sum as i16;
        }

        // Fold x^p ≡ x + 1 with a single mod-3 freeze per output coefficient: fg[i] (i ≥ p)
        // contributes to outputs i-p and i-p+1, and no fold target is itself ≥ p, so every
        // output is independent.
        h[0] = mod3::freeze(i32::from(fg[0]) + i32::from(fg[p]));
        for k in 1..p {
            h[k] = mod3::freeze(i32::from(fg[k]) + i32::from(fg[k + p]) + i32::from(fg[k + p - 1]));
        }

        // At least one operand is secret at every call site — wipe the reversed copy and
        // the product scratch.
        g_rev.zeroize();
        fg.zeroize();
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* so the test needs no RNG crates or features.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn random_ternary(p: usize, seed: u64) -> Vec<i8> {
        let mut s = seed | 1;
        (0..p).map(|_| ((next(&mut s) % 3) as i8) - 1).collect()
    }

    /// Compare every compiled-in SIMD kernel against the scalar reference. Catches the class
    /// of bug the KAT/roundtrip suite can miss when run with `--all-features`, which enables
    /// `force-scalar` and silently compiles the SIMD kernels out of the test entirely.
    fn check_case(p: usize, f: &[i8], g: &[i8], label: &str) {
        let mut want = vec![0i8; p];
        mult_scalar(&mut want, f, g, p);

        #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
        {
            let mut got = vec![0i8; p];
            // SAFETY: NEON is baseline on aarch64
            unsafe { mult_neon(&mut got, f, g, p) };
            assert_eq!(got, want, "r3 mult_neon vs scalar: {label} p={p}");
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        if crate::cpu::has_avx2() {
            let mut got = vec![0i8; p];
            // SAFETY: AVX2 support confirmed by has_avx2()
            unsafe { mult_avx2(&mut got, f, g, p) };
            assert_eq!(got, want, "r3 mult_avx2 vs scalar: {label} p={p}");
        }

        let mut got = vec![0i8; p];
        mult(&mut got, f, g, p);
        assert_eq!(got, want, "dispatched r3 mult vs scalar: {label} p={p}");
    }

    #[test]
    fn simd_mult_matches_scalar_random() {
        for p in [653usize, 761, 857, 953, 1013, 1277] {
            for seed in 1..=8u64 {
                let f = random_ternary(p, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
                let g = random_ternary(p, seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
                check_case(p, &f, &g, "random");
            }
        }
    }

    /// All-ones operands maximize accumulator magnitude, probing the i16 headroom the NEON
    /// widening-accumulate staging depends on.
    #[test]
    fn simd_mult_extremes_match_scalar() {
        for p in [653usize, 761, 857, 953, 1013, 1277] {
            let ones = vec![1i8; p];
            let neg = vec![-1i8; p];
            check_case(p, &ones, &ones, "all +1");
            check_case(p, &ones, &neg, "+1 × -1");
        }
    }
}
