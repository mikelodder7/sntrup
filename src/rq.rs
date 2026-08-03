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

/// Column-major schoolbook multiplication with AVX2.
/// Processes 8 i32 multiply-accumulates per SIMD instruction.
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

        // Pad to multiples of 8 so SIMD loops need no remainder handling
        let g_pad_len = (p + 7) & !7;
        let fg_pad_len = p + g_pad_len;
        let fg_len = p * 2 - 1;

        // Sign-extend g to i32 once, padded. This does not depend on j, so computing it
        // outside the j-loop (rather than re-extending the same bytes on every one of the p
        // outer iterations) turns the inner loop's load into a single direct i32 load instead
        // of a narrow load plus a sign-extending convert on every iteration.
        let mut g_pad = vec![0i32; g_pad_len];
        for i in 0..p {
            g_pad[i] = g[i] as i32;
        }
        let mut fg = vec![0i32; fg_pad_len];

        // Accumulate f[j]*g[k] into fg[j+k]
        for j in 0..p {
            let fj = _mm256_set1_epi32(f[j] as i32);
            let mut k = 0usize;
            while k < g_pad_len {
                let gk = _mm256_loadu_si256(g_pad.as_ptr().add(k) as *const __m256i);
                let prod = _mm256_mullo_epi32(fj, gk);
                let acc = _mm256_loadu_si256(fg.as_ptr().add(j + k) as *const __m256i);
                _mm256_storeu_si256(
                    fg.as_mut_ptr().add(j + k) as *mut __m256i,
                    _mm256_add_epi32(acc, prod),
                );
                k += 8;
            }
        }

        // Vectorized Barrett freeze: i32 -> i16
        let qv = _mm256_set1_epi32(q);
        let kb1 = _mm256_set1_epi32(b1);
        let kb2 = _mm256_set1_epi32(b2);
        let k134m = _mm256_set1_epi32(134_217_728);

        let mut fg16 = vec![0i16; fg_len];
        let mut i = 0usize;
        while i + 16 <= fg_len {
            let a0 = _mm256_loadu_si256(fg.as_ptr().add(i) as *const __m256i);
            let a1 = _mm256_loadu_si256(fg.as_ptr().add(i + 8) as *const __m256i);

            // freeze(a) = a - Q*((b1*a)>>20) then b - Q*((b2*b+134M)>>28)
            let t = _mm256_srai_epi32(_mm256_mullo_epi32(a0, kb1), 20);
            let b0 = _mm256_sub_epi32(a0, _mm256_mullo_epi32(t, qv));
            let t = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b0, kb2), k134m), 28);
            let r0 = _mm256_sub_epi32(b0, _mm256_mullo_epi32(t, qv));

            let t = _mm256_srai_epi32(_mm256_mullo_epi32(a1, kb1), 20);
            let b1v = _mm256_sub_epi32(a1, _mm256_mullo_epi32(t, qv));
            let t = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b1v, kb2), k134m), 28);
            let r1 = _mm256_sub_epi32(b1v, _mm256_mullo_epi32(t, qv));

            // Pack 8+8 i32 -> 16 i16 and fix AVX2 lane ordering
            let packed = _mm256_permute4x64_epi64(_mm256_packs_epi32(r0, r1), 0xD8);
            _mm256_storeu_si256(fg16.as_mut_ptr().add(i) as *mut __m256i, packed);
            i += 16;
        }
        while i < fg_len {
            fg16[i] = modq::freeze(fg[i], q, b1, b2);
            i += 1;
        }

        // Reduction (scalar -- sequential dependencies prevent vectorization)
        for i in (p..(p * 2) - 1).rev() {
            fg16[i - p] = modq::freeze(fg16[i - p] as i32 + fg16[i] as i32, q, b1, b2);
            fg16[i - p + 1] = modq::freeze(fg16[i - p + 1] as i32 + fg16[i] as i32, q, b1, b2);
        }
        h[..p].copy_from_slice(&fg16[..p]);
    }
}

/// Column-major schoolbook multiplication with NEON.
///
/// `vmlal_n_s16`/`vmlal_high_n_s16` widen-multiply i16 inputs directly into the i32
/// accumulator in one instruction, processing 8 elements per 128-bit register instead of the 4
/// an i32-typed `g` would hold — disassembling PQClean's reference showed clang's
/// autovectorizer reaching for the same instruction pair, which is what let its "portable" C
/// come close to this crate's earlier i32-typed hand-written NEON kernel; switching to i16
/// closed most of the remaining gap.
///
/// Two row-major variants were also tried, informed by the same disassembly: one with an i32
/// accumulator and a single dependency chain per row (much slower — the per-row `vaddvq_s32`
/// horizontal reduction, paid `2p-1` times, cost more than the memory traffic it removed), and
/// one combining the i16 widening-MAC above with two independent accumulator chains per row
/// (matching clang's four-chain unrolling) to hide that latency. The second one measured
/// statistically tied with column-major here — memory traffic apparently stopped being the
/// bottleneck once each MAC did twice the work, at which point the two structures converge.
/// Column-major is kept for being the simpler of the two at equal speed.
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

        // Pad to multiples of 8 so SIMD loops need no remainder handling
        let g_pad_len = (p + 7) & !7;
        let fg_pad_len = p + g_pad_len;
        let fg_len = p * 2 - 1;

        // Sign-extend g to i16 once, padded (`f` is already Fq-range i16, both operands fit
        // without the i32 widening this crate used previously). This does not depend on j, so
        // computing it outside the j-loop avoids re-extending the same bytes on every one of
        // the p outer iterations.
        let mut g_pad = vec![0i16; g_pad_len];
        for i in 0..p {
            g_pad[i] = g[i] as i16;
        }
        let mut fg = vec![0i32; fg_pad_len];

        // Accumulate f[j]*g[k] into fg[j+k]. `vmlal_n_s16`/`vmlal_high_n_s16` widen-multiply
        // i16 inputs directly into the i32 accumulator in one instruction, processing 8
        // elements per 128-bit register instead of the 4 an i32-typed `g` would hold —
        // disassembling PQClean's reference showed clang's autovectorizer reaching for the
        // same instruction pair, which is what let its "portable" C match this crate's
        // hand-written i32 NEON kernel.
        for j in 0..p {
            let fj = f[j];
            let mut k = 0usize;
            while k + 8 <= g_pad_len {
                let gk = vld1q_s16(g_pad.as_ptr().add(k));
                let acc_lo = vld1q_s32(fg.as_ptr().add(j + k));
                let acc_hi = vld1q_s32(fg.as_ptr().add(j + k + 4));
                vst1q_s32(
                    fg.as_mut_ptr().add(j + k),
                    vmlal_n_s16(acc_lo, vget_low_s16(gk), fj),
                );
                vst1q_s32(
                    fg.as_mut_ptr().add(j + k + 4),
                    vmlal_high_n_s16(acc_hi, gk, fj),
                );
                k += 8;
            }
        }

        // Vectorized Barrett freeze: i32 -> i16
        let qv = vdupq_n_s32(q);
        let kb1 = vdupq_n_s32(b1);
        let kb2 = vdupq_n_s32(b2);
        let k134m = vdupq_n_s32(134_217_728);

        let mut fg16 = vec![0i16; fg_len];
        let mut i = 0usize;
        while i + 8 <= fg_len {
            // Process 8 values: two batches of 4 i32 -> 8 i16
            let a0 = vld1q_s32(fg.as_ptr().add(i));
            let a1 = vld1q_s32(fg.as_ptr().add(i + 4));

            let t = vshrq_n_s32(vmulq_s32(a0, kb1), 20);
            let b0 = vsubq_s32(a0, vmulq_s32(t, qv));
            let t = vshrq_n_s32(vaddq_s32(vmulq_s32(b0, kb2), k134m), 28);
            let r0 = vsubq_s32(b0, vmulq_s32(t, qv));

            let t = vshrq_n_s32(vmulq_s32(a1, kb1), 20);
            let b1v = vsubq_s32(a1, vmulq_s32(t, qv));
            let t = vshrq_n_s32(vaddq_s32(vmulq_s32(b1v, kb2), k134m), 28);
            let r1 = vsubq_s32(b1v, vmulq_s32(t, qv));

            // Pack 4+4 i32 -> 8 i16 (naturally ordered, no permute needed)
            let packed = vcombine_s16(vmovn_s32(r0), vmovn_s32(r1));
            vst1q_s16(fg16.as_mut_ptr().add(i), packed);
            i += 8;
        }
        while i < fg_len {
            fg16[i] = modq::freeze(fg[i], q, b1, b2);
            i += 1;
        }

        // Reduction (scalar -- sequential dependencies prevent vectorization)
        for i in (p..(p * 2) - 1).rev() {
            fg16[i - p] = modq::freeze(fg16[i - p] as i32 + fg16[i] as i32, q, b1, b2);
            fg16[i - p + 1] = modq::freeze(fg16[i - p + 1] as i32 + fg16[i] as i32, q, b1, b2);
        }
        h[..p].copy_from_slice(&fg16[..p]);
    }
}
