//! Fast volatile wiping of plain-integer scratch buffers.

use zeroize::{DefaultIsZeroes, Zeroize};

/// Wipe a plain-integer buffer with volatile stores, eight bytes at a time.
///
/// [`Zeroize`] on a slice issues one volatile store *per element*, which the
/// compiler is not permitted to merge or vectorize. Across the multi-kilobyte
/// scratch buffers the SIMD kernels use, that granularity — not the wiping
/// itself — dominated the cost: measured at roughly 18% of decapsulation for the
/// NTT multiply alone.
///
/// Re-viewing the buffer as `[u64]` keeps the volatile guarantee exactly (any
/// unaligned head and tail are still wiped, just at their own width) while
/// issuing a quarter as many stores for `i16` data and an eighth for `i8`.
#[inline]
pub(crate) fn wipe<T: Zeroize + DefaultIsZeroes>(buf: &mut [T]) {
    // SAFETY: `T` is a plain integer with no padding and no invalid bit
    // patterns, so viewing the buffer's bytes as `u64` is valid. `align_to_mut`
    // returns whatever head and tail cannot be covered at that width, and
    // zeroize only ever writes.
    unsafe {
        let (head, mid, tail) = buf.align_to_mut::<u64>();
        head.zeroize();
        mid.zeroize();
        tail.zeroize();
    }
}
