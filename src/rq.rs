pub mod encoding;
pub mod modq;
mod vector;

use crate::ct::{smaller_mask, swap_int};
use crate::params::SntrupParameters;

#[allow(clippy::cast_possible_wrap)]
pub fn reciprocal3(s: &[i8], params: &SntrupParameters) -> Vec<i16> {
    let p = params.p;
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;
    let loops = 2 * p + 1;

    let mut r = vec![0i16; p];
    let mut f = vec![0i16; p + 1];
    f[0] = -1;
    f[1] = -1;
    f[p] = 1;
    let mut g = vec![0i16; p + 1];
    for i in 0..p {
        g[i] = (3 * s[i]) as i16;
    }
    let mut d = p as isize;
    let mut e = p as isize;
    let mut u = vec![0i16; loops + 1];
    let mut v = vec![0i16; loops + 1];
    v[0] = 1;

    for _ in 0..loops {
        let c = modq::quotient(g[p], f[p], q, b1, b2);
        vector::minus_product_shift(&mut g, p + 1, &f, c, q, b1, b2);
        vector::minus_product_shift(&mut v, loops + 1, &u, c, q, b1, b2);
        e -= 1;
        let m = smaller_mask(e, d) & modq::mask_set(g[p]);
        let (e_tmp, d_tmp) = swap_int(e, d, m);
        e = e_tmp;
        d = d_tmp;
        vector::swap(&mut f, &mut g, p + 1, m);
        vector::swap(&mut u, &mut v, loops + 1, m);
    }
    vector::product(
        &mut r,
        p,
        &u[p..],
        modq::reciprocal(f[p], q, b1, b2),
        q,
        b1,
        b2,
    );
    // Note: unlike r3::reciprocal, no invertibility check is returned here.
    // For these parameter sets q is prime and x^p - x - 1 is irreducible mod q,
    // so R/q is a field and the weight-w secret f is always invertible — the
    // reciprocal never fails, so there is no failure mask to propagate.
    r
}

#[allow(clippy::cast_possible_truncation)]
pub fn round3(h: &mut [i16], params: &SntrupParameters) {
    let q12 = params.q12;
    for coeff in h.iter_mut() {
        let inner = 21846i32 * (*coeff as i32 + q12);
        *coeff = (((inner + 32768) >> 16) * 3 - q12) as i16;
    }
}

#[allow(unsafe_code)]
pub fn mult(h: &mut [i16], f: &[i16], g: &[i8], params: &SntrupParameters) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return mult_avx2(h, f, g, params);
        }
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return mult_neon(h, f, g, params);
    }
    #[allow(unreachable_code)]
    mult_scalar(h, f, g, params);
}

fn mult_scalar(h: &mut [i16], f: &[i16], g: &[i8], params: &SntrupParameters) {
    let p = params.p;
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;

    let mut fg = vec![0i16; p * 2 - 1];
    for i in 0..p {
        let mut r = 0i32;
        for j in 0..=i {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = modq::freeze(r, q, b1, b2);
    }
    for i in p..(p * 2 - 1) {
        let mut r = 0i32;
        for j in (i - p + 1)..p {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = modq::freeze(r, q, b1, b2);
    }
    for i in (p..(p * 2) - 1).rev() {
        fg[i - p] = modq::freeze(fg[i - p] as i32 + fg[i] as i32, q, b1, b2);
        fg[i - p + 1] = modq::freeze(fg[i - p + 1] as i32 + fg[i] as i32, q, b1, b2);
    }
    h[..p].copy_from_slice(&fg[..p]);
}

/// Row-major schoolbook multiplication with AVX2.
///
/// Same structure as the NEON kernel below (see its doc comment): contiguous dot products over
/// `f` and a pre-reversed `g`, four independent accumulators, one store per output
/// coefficient, and the `x^p ≡ x + 1` fold applied to raw sums with vectorized freezes.
///
/// The widening multiply-accumulate here is `_mm256_madd_epi16` (pmaddwd): i16×i16 products
/// pairwise-summed into i32 lanes — 16 multiply-accumulates per instruction, double the old
/// column-major kernel's 8-lane `_mm256_mullo_epi32` density. A dot product only needs the
/// total, so pmaddwd's pairwise fold loses nothing. (An earlier note in this crate claimed
/// AVX2 has no i16-widening MAC — wrong: pmaddwd is exactly that for dot-product shapes.)
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::needless_range_loop
)]
unsafe fn mult_avx2(h: &mut [i16], f: &[i16], g: &[i8], params: &SntrupParameters) {
    unsafe {
        use core::arch::x86_64::*;

        let p = params.p;
        let q = params.q;
        let b1 = params.barrett1;
        let b2 = params.barrett2;
        let fg_len = p * 2 - 1;

        let mut g_rev = vec![0i16; p];
        for i in 0..p {
            g_rev[i] = g[p - 1 - i] as i16;
        }

        // Raw i32 convolution sums, padded with one zero so the fold below may read
        // `fg32[k + p]` unconditionally at `k = p - 1`.
        let mut fg32 = vec![0i32; fg_len + 1];
        for (i, out) in fg32[..fg_len].iter_mut().enumerate() {
            let jlo = i.saturating_sub(p - 1);
            let len = i.min(p - 1) - jlo + 1;
            let fp = f.as_ptr().add(jlo);
            let gp = g_rev.as_ptr().add(p - 1 - i + jlo);

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
            *out = sum;
        }

        let qv = _mm256_set1_epi32(q);
        let kb1 = _mm256_set1_epi32(b1);
        let kb2 = _mm256_set1_epi32(b2);
        let k134m = _mm256_set1_epi32(134_217_728);

        // Vectorized in-place Barrett freeze of the raw sums (the pad entry stays zero).
        let mut i = 0usize;
        while i + 8 <= fg_len {
            let a = _mm256_loadu_si256(fg32.as_ptr().add(i) as *const __m256i);
            let t = _mm256_srai_epi32(_mm256_mullo_epi32(a, kb1), 20);
            let b = _mm256_sub_epi32(a, _mm256_mullo_epi32(t, qv));
            let t = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b, kb2), k134m), 28);
            _mm256_storeu_si256(
                fg32.as_mut_ptr().add(i) as *mut __m256i,
                _mm256_sub_epi32(b, _mm256_mullo_epi32(t, qv)),
            );
            i += 8;
        }
        while i < fg_len {
            fg32[i] = modq::freeze(fg32[i], q, b1, b2) as i32;
            i += 1;
        }

        // Fold x^p ≡ x + 1 and freeze once more: fg32[i] (i ≥ p) contributes to outputs i-p
        // and i-p+1, so h[k] = freeze(fg32[k] + fg32[k+p] + fg32[k+p-1]) for k ≥ 1, and
        // h[0] = freeze(fg32[0] + fg32[p]).
        h[0] = modq::freeze(fg32[0] + fg32[p], q, b1, b2);
        let mut k = 1usize;
        while k + 8 <= p {
            let a = _mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_loadu_si256(fg32.as_ptr().add(k) as *const __m256i),
                    _mm256_loadu_si256(fg32.as_ptr().add(k + p) as *const __m256i),
                ),
                _mm256_loadu_si256(fg32.as_ptr().add(k + p - 1) as *const __m256i),
            );
            let t = _mm256_srai_epi32(_mm256_mullo_epi32(a, kb1), 20);
            let b = _mm256_sub_epi32(a, _mm256_mullo_epi32(t, qv));
            let t = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b, kb2), k134m), 28);
            let r = _mm256_sub_epi32(b, _mm256_mullo_epi32(t, qv));
            let packed = _mm_packs_epi32(_mm256_castsi256_si128(r), _mm256_extracti128_si256(r, 1));
            _mm_storeu_si128(h.as_mut_ptr().add(k) as *mut __m128i, packed);
            k += 8;
        }
        while k < p {
            h[k] = modq::freeze(fg32[k] + fg32[k + p] + fg32[k + p - 1], q, b1, b2);
            k += 1;
        }
    }
}

/// Row-major schoolbook multiplication with NEON.
///
/// Each output coefficient's convolution sum is a contiguous dot product held in registers and
/// written to memory once. `g` is pre-reversed (`g_rev[k] = g[p-1-k]`) so row `i`'s terms
/// `f[j]·g[i-j]` become `f[jlo+t]·g_rev[g0+t]` — both operands advance together.
///
/// The inner loop uses `vmlal_s16`/`vmlal_high_s16` (i16×i16→i32 widening multiply-accumulate,
/// 8 lanes per instruction pair) across EIGHT independent accumulators, mirroring the structure
/// clang's autovectorizer emits for PQClean's reference C (`smlal`/`smlal2` over `v0`–`v7`):
/// with multi-cycle MAC latency and multiple SIMD pipes, ~8 independent chains are needed to
/// keep the pipes full. An earlier 2-chain attempt (each chain serially feeding its own low and
/// high halves) was latency-bound and only tied the previous column-major kernel; 8 chains is
/// what makes row-major win. Row-major also eliminates the column-major kernel's
/// store-to-load-forwarding hazard, where each `j` iteration reloaded accumulator vectors
/// partially overlapping the previous iteration's stores at a one-element offset.
///
/// Raw i32 row sums are kept unreduced (bounded by `p·(q-1)/2 < 5.1M`, inside the Barrett
/// window), frozen once in a vectorized pass, then the `x^p ≡ x + 1` fold adds three
/// already-frozen values (|sum| ≤ 3·(q-1)/2) with one final vectorized freeze — two freezes
/// per output coefficient where the reference implementation spends three, and no serial
/// dependency anywhere: `fg[i]` for `i ≥ p` is never itself a fold target, so every fold lane
/// is independent.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::needless_range_loop
)]
unsafe fn mult_neon(h: &mut [i16], f: &[i16], g: &[i8], params: &SntrupParameters) {
    unsafe {
        use core::arch::aarch64::*;

        let p = params.p;
        let q = params.q;
        let b1 = params.barrett1;
        let b2 = params.barrett2;
        let fg_len = p * 2 - 1;

        let mut g_rev = vec![0i16; p];
        for i in 0..p {
            g_rev[i] = g[p - 1 - i] as i16;
        }

        // Raw i32 convolution sums, padded with one zero so the fold below may read
        // `fg32[k + p]` unconditionally at `k = p - 1`.
        let mut fg32 = vec![0i32; fg_len + 1];
        for (i, out) in fg32[..fg_len].iter_mut().enumerate() {
            let jlo = i.saturating_sub(p - 1);
            let len = i.min(p - 1) - jlo + 1;
            let fp = f.as_ptr().add(jlo);
            let gp = g_rev.as_ptr().add(p - 1 - i + jlo);

            let mut acc0 = vdupq_n_s32(0);
            let mut acc1 = vdupq_n_s32(0);
            let mut acc2 = vdupq_n_s32(0);
            let mut acc3 = vdupq_n_s32(0);
            let mut acc4 = vdupq_n_s32(0);
            let mut acc5 = vdupq_n_s32(0);
            let mut acc6 = vdupq_n_s32(0);
            let mut acc7 = vdupq_n_s32(0);
            let mut k = 0usize;
            while k + 32 <= len {
                let f0 = vld1q_s16(fp.add(k));
                let f1 = vld1q_s16(fp.add(k + 8));
                let f2 = vld1q_s16(fp.add(k + 16));
                let f3 = vld1q_s16(fp.add(k + 24));
                let g0 = vld1q_s16(gp.add(k));
                let g1 = vld1q_s16(gp.add(k + 8));
                let g2 = vld1q_s16(gp.add(k + 16));
                let g3 = vld1q_s16(gp.add(k + 24));
                acc0 = vmlal_s16(acc0, vget_low_s16(f0), vget_low_s16(g0));
                acc1 = vmlal_high_s16(acc1, f0, g0);
                acc2 = vmlal_s16(acc2, vget_low_s16(f1), vget_low_s16(g1));
                acc3 = vmlal_high_s16(acc3, f1, g1);
                acc4 = vmlal_s16(acc4, vget_low_s16(f2), vget_low_s16(g2));
                acc5 = vmlal_high_s16(acc5, f2, g2);
                acc6 = vmlal_s16(acc6, vget_low_s16(f3), vget_low_s16(g3));
                acc7 = vmlal_high_s16(acc7, f3, g3);
                k += 32;
            }
            while k + 8 <= len {
                let f0 = vld1q_s16(fp.add(k));
                let g0 = vld1q_s16(gp.add(k));
                acc0 = vmlal_s16(acc0, vget_low_s16(f0), vget_low_s16(g0));
                acc1 = vmlal_high_s16(acc1, f0, g0);
                k += 8;
            }
            let total = vaddq_s32(
                vaddq_s32(vaddq_s32(acc0, acc1), vaddq_s32(acc2, acc3)),
                vaddq_s32(vaddq_s32(acc4, acc5), vaddq_s32(acc6, acc7)),
            );
            let mut sum = vaddvq_s32(total);
            while k < len {
                sum += *fp.add(k) as i32 * *gp.add(k) as i32;
                k += 1;
            }
            *out = sum;
        }

        let qv = vdupq_n_s32(q);
        let kb1 = vdupq_n_s32(b1);
        let kb2 = vdupq_n_s32(b2);
        let k134m = vdupq_n_s32(134_217_728);

        // Vectorized in-place Barrett freeze of the raw sums (the pad entry stays zero).
        let mut i = 0usize;
        while i + 4 <= fg_len {
            let a = vld1q_s32(fg32.as_ptr().add(i));
            let t = vshrq_n_s32(vmulq_s32(a, kb1), 20);
            let b = vsubq_s32(a, vmulq_s32(t, qv));
            let t = vshrq_n_s32(vaddq_s32(vmulq_s32(b, kb2), k134m), 28);
            vst1q_s32(fg32.as_mut_ptr().add(i), vsubq_s32(b, vmulq_s32(t, qv)));
            i += 4;
        }
        while i < fg_len {
            fg32[i] = modq::freeze(fg32[i], q, b1, b2) as i32;
            i += 1;
        }

        // Fold x^p ≡ x + 1 and freeze once more: fg32[i] (i ≥ p) contributes to outputs i-p
        // and i-p+1, so h[k] = freeze(fg32[k] + fg32[k+p] + fg32[k+p-1]) for k ≥ 1, and
        // h[0] = freeze(fg32[0] + fg32[p]).
        h[0] = modq::freeze(fg32[0] + fg32[p], q, b1, b2);
        let mut k = 1usize;
        while k + 4 <= p {
            let a = vaddq_s32(
                vaddq_s32(
                    vld1q_s32(fg32.as_ptr().add(k)),
                    vld1q_s32(fg32.as_ptr().add(k + p)),
                ),
                vld1q_s32(fg32.as_ptr().add(k + p - 1)),
            );
            let t = vshrq_n_s32(vmulq_s32(a, kb1), 20);
            let b = vsubq_s32(a, vmulq_s32(t, qv));
            let t = vshrq_n_s32(vaddq_s32(vmulq_s32(b, kb2), k134m), 28);
            let r = vsubq_s32(b, vmulq_s32(t, qv));
            vst1_s16(h.as_mut_ptr().add(k), vmovn_s32(r));
            k += 4;
        }
        while k < p {
            h[k] = modq::freeze(fg32[k] + fg32[k + p] + fg32[k + p - 1], q, b1, b2);
            k += 1;
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;
    use crate::params::SntrupParams;

    /// Deterministic xorshift64* so the test needs no RNG crates or features.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn random_case(params: &SntrupParameters, seed: u64) -> (Vec<i16>, Vec<i8>) {
        let mut s = seed | 1;
        let q12 = params.q12;
        let f = (0..params.p)
            .map(|_| ((next(&mut s) % (2 * q12 as u64 + 1)) as i32 - q12) as i16)
            .collect();
        let g = (0..params.p)
            .map(|_| ((next(&mut s) % 3) as i8) - 1)
            .collect();
        (f, g)
    }

    fn all_params() -> [&'static SntrupParameters; 6] {
        [
            crate::params::Sntrup653Params::params(),
            crate::params::Sntrup761Params::params(),
            crate::params::Sntrup857Params::params(),
            crate::params::Sntrup953Params::params(),
            crate::params::Sntrup1013Params::params(),
            crate::params::Sntrup1277Params::params(),
        ]
    }

    /// Compare every compiled-in SIMD kernel against the scalar reference. Catches the class
    /// of bug the KAT/roundtrip suite can miss when run with `--all-features`, which enables
    /// `force-scalar` and silently compiles the SIMD kernels out of the test entirely.
    fn check_case(params: &SntrupParameters, f: &[i16], g: &[i8], label: &str) {
        let p = params.p;
        let mut want = vec![0i16; p];
        mult_scalar(&mut want, f, g, params);

        #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
        {
            let mut got = vec![0i16; p];
            // SAFETY: NEON is baseline on aarch64
            unsafe { mult_neon(&mut got, f, g, params) };
            assert_eq!(got, want, "mult_neon vs scalar: {label} p={p}");
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        if crate::cpu::has_avx2() {
            let mut got = vec![0i16; p];
            // SAFETY: AVX2 support confirmed by has_avx2()
            unsafe { mult_avx2(&mut got, f, g, params) };
            assert_eq!(got, want, "mult_avx2 vs scalar: {label} p={p}");
        }

        let mut got = vec![0i16; p];
        mult(&mut got, f, g, params);
        assert_eq!(got, want, "dispatched mult vs scalar: {label} p={p}");
    }

    #[test]
    fn simd_mult_matches_scalar_random() {
        for params in all_params() {
            for seed in 1..=8u64 {
                let (f, g) = random_case(params, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
                check_case(params, &f, &g, "random");
            }
        }
    }

    /// Extremes: `f` saturated at ±(q-1)/2 and `g` all ±1 maximize accumulator magnitude,
    /// probing the overflow headroom the SIMD kernels' Barrett-freeze staging depends on.
    #[test]
    fn simd_mult_extremes_match_scalar() {
        for params in all_params() {
            let q12 = params.q12 as i16;
            let f_max: Vec<i16> = (0..params.p).map(|_| q12).collect();
            let f_alt: Vec<i16> = (0..params.p)
                .map(|i| if i % 2 == 0 { q12 } else { -q12 })
                .collect();
            let g_ones = vec![1i8; params.p];
            let g_neg = vec![-1i8; params.p];
            check_case(params, &f_max, &g_ones, "f=+max g=+1");
            check_case(params, &f_max, &g_neg, "f=+max g=-1");
            check_case(params, &f_alt, &g_ones, "f=alt g=+1");
        }
    }
}
