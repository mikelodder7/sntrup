# One complete run

**Machine:** Apple M2 Max, macOS (Darwin 25.5.0), native `aarch64-apple-darwin` — NEON is a
baseline guarantee of the architecture, so all three implementations below use their
NEON/portable-C paths; none of this run exercises AVX2 (x86_64-only).

**Toolchain:** `rustc 1.97.1`, `cargo 1.97.1`, release profile, default Cargo features for
every crate except `pqcrypto-ntruprime` (`avx2` feature left off — see the README).

**Command:** `cargo bench --manifest-path benches/comparison/Cargo.toml`

| Operation    | `sntrup` (this crate) | PQClean (clean C) | liboqs (clean C) |
|--------------|------------------------|--------------------|-------------------|
| keypair      | **1.341 ms**           | 1.780 ms           | 1.827 ms          |
| encapsulate  | **50.00 µs**           | 51.54 µs           | 51.39 µs          |
| decapsulate  | **84.52 µs**           | 90.20 µs           | 90.54 µs          |

Bold marks the fastest of the three per row. Each figure is Criterion's reported mean. This
crate is the fastest of the three on every operation — keypair by 25%, encapsulate by ~3%,
decapsulate by ~6% — *while also zeroizing every secret-derived scratch buffer, which the C
references do not do* (their kernels leave secret-holding stack arrays unwiped). At the start
of this investigation it trailed the C references by 1.86x on encapsulate and 2.06x on
decapsulate. Before the hardening pass (no scratch wiping, matching the C references'
behavior) the margins were wider: encapsulate 45.4 µs (15% faster than PQClean) and
decapsulate 77.8 µs (16% faster); the wipes cost ~11% because the `zeroize` crate's
per-element volatile writes are deliberately opaque to the optimizer. That trade was accepted
knowingly: audited-crate wipes over hand-rolled `unsafe` memset-and-fence.

## How the gap was closed

Encapsulate and decapsulate are dominated by the O(p²) schoolbook polynomial multiplies
(`rq::mult`, plus `r3::mult` on the decapsulate side); an `Instant`-based internal breakdown
put `rq::mult` at ~78 of encapsulate's ~100 µs at the outset, and `/usr/bin/sample` later
confirmed it at 86% of the call tree with heap allocation under 1% — the multiply was always
the whole story. Four fixes landed, in three rounds:

**Round 1, fix 1 — hoist a redundant conversion out of the hot loop.** `g` was re-sign-extended
i8→i32 inside the outer loop, once per `f[j]` (761×) instead of once upfront. −33% off `mult`.

**Round 1, fix 2 — use the widening multiply-accumulate.** Disassembling PQClean's compiled
"portable" C showed clang autovectorizing it with `smlal`/`smlal2` (NEON's i16×i16→i32 widening
MAC, 8 lanes/instruction); this crate stored operands as i32 and used 4-lane `vmlaq_s32` for no
reason — both operands fit i16. Switching to `vmlal_n_s16`/`vmlal_high_n_s16` (and
`vmlal_s8`/`vmlal_high_s8` in `r3::mult`) closed most of the remaining gap: ~1.9x → ~1.3x.

**Round 3, fix 3 — EIGHT independent accumulator chains (the decisive one).** The same
disassembly showed clang's inner loop spreading `smlal`/`smlal2` across eight accumulator
registers (`v0`–`v7`). A round-2 "row-major with 2 chains" attempt had each chain serially
feeding its own low/high halves — effective ILP of 2, latency-bound, and it merely tied the
column-major kernel, which wrongly suggested row-major had nothing left. Rebuilding row-major
with a full 8 independent chains (each `vmlal`/`vmlal_high` targeting its own register, 32
elements per iteration) made it win decisively: each output coefficient's dot product lives in
registers and hits memory once, eliminating the column-major kernel's per-iteration
store-to-load-forwarding hazard (every `j` iteration reloaded vectors partially overlapping the
previous iteration's stores at a 1-element offset), and the 8 chains keep the MAC pipes full.
`rq::mult` and `r3::mult` both got this shape.

**Round 3, fix 4 — fewer freezes.** The reference freezes every convolution coefficient, then
freezes twice more (serially) folding `x^p ≡ x+1`. Raw i32 row sums stay inside the
Barrett-freeze validity window for every parameter set (max `p·(q-1)/2` ≈ 5.03M for sntrup1277,
window ±7M — though the *folded* 3-term sum would overflow the second Barrett step for the
largest sets, which is why the fold happens between two vectorized freezes rather than before a
single one). Since no fold target is itself ≥ p, every fold lane is independent: two fully
vectorized freezes per output instead of one vectorized + two serial scalar ones.

**AVX2 got the same rewrite** via `_mm256_madd_epi16` (pmaddwd): i16×i16 products
pairwise-summed into i32 lanes, 16 MACs per instruction — a dot product only needs the total,
so the pairwise fold loses nothing. (Round 2's notes claimed AVX2 has no i16-widening MAC and
skipped it; that was wrong — pmaddwd is exactly that for dot-product shapes.) Verified
correct on all parameter sets by running the differential tests under Rosetta with detection
force-enabled; real x86 timing remains unmeasured in this environment, but the kernel now has
double the MAC density of its predecessor and no store-forwarding hazard.

## Guardrails added

`src/rq.rs` and `src/r3.rs` now carry permanent differential tests comparing every compiled-in
SIMD kernel (and the dispatched entry point) against the scalar reference, across all six
parameter sets, on random and extreme (±(q-1)/2 × ±1) inputs. These exist because round 2
produced a batching variant whose overlapping-store bug passed `cargo test --release
--all-features` — `--all-features` enables `force-scalar`, which compiles the SIMD kernels out
of the test binary entirely. **Never rely on `--all-features` alone to validate SIMD changes in
this crate**; run `--features kem,serde,std` (SIMD active) and `...,force-scalar` (scalar)
separately. The differential tests fail loudly in the first configuration if a kernel drifts.

## Dead ends (measured, reverted — so the next attempt doesn't re-walk them)

- FMA-fusing the old i32 column-major kernel (`vmlaq_s32`): no change.
- ILP-batching extra k-windows in column-major (two variants, rounds 1–2): flat to slightly
  worse — the bottleneck was the store-forwarding hazard, which more work per iteration
  doesn't remove.
- Row-major with a single i32 chain (round 1): much slower; per-row `vaddvq_s32` cost more
  than the memory traffic saved. Right idea, an order of magnitude short on ILP.
- Row-major with 2 serial-pair chains (round 2): tied column-major. Same idea, half short.
- Batching two adjacent `j` in column-major (round 2): correctness bug (overlapping
  read-modify-write), caught only by direct kernel-vs-scalar comparison — see Guardrails.

## Hardening pass

After the performance work, every secret-derived heap temporary the crate allocates is now
wiped with the `zeroize` crate before it is freed: the multiply kernels' reversed-operand
copies and product scratch (`rq::mult`, `r3::mult`, all scalar/NEON/AVX2 variants), both
`reciprocal` functions' Euclidean state, `random_tsmall`'s sorted tagged randomness,
`rounded_encode`'s in-place working representation (secret-derived on the decapsulation
path), and the SHA-512 helpers' 64-byte digests and inner-hash temporaries (the discarded
upper 32 bytes are secret-derived). Known residual limitation, documented on the function:
`generate_key_deterministic`'s ChaCha20 RNG state is dropped unwiped because `rand_chacha`
has no zeroization support.

## This crate's own sweep (native, NEON active, default features)

`cargo bench` (`benches/mod.rs`), same machine, current state (with scratch zeroization):

| Parameter set | keygen    | encapsulate | decapsulate |
|----------------|-----------|-------------|-------------|
| sntrup761      | 1.322 ms  | 50.56 µs    | 84.14 µs    |
| sntrup1277     | 3.651 ms  | 111.2 µs    | 210.0 µs    |

At the start of the investigation: sntrup761 encapsulate 101.4 µs / decapsulate 196.1 µs;
sntrup1277 encapsulate 252.7 µs / decapsulate 525.0 µs. **2.26x / 2.58x faster** (761) and
**2.46x / 2.67x faster** (1277), every change bit-for-bit verified against the scalar
reference, the KAT vectors, and the round-trip/serde suites on both the NEON and forced-AVX2
paths.

---

# x86_64 run (2026-08-03)

**Machine:** AMD Ryzen AI 9 HX 370 (Zen 5 "Strix Point", AVX2 + AVX-VNNI + AVX-512),
Fedora Linux, benchmark pinned to one 5.16 GHz Zen 5 core (`taskset -c 2`). Note: a video
call ran concurrently during the final pass; the before/after deltas below are same-session
A/B comparisons, but absolute numbers carry a few percent of ambient noise.

**Toolchain:** `rustc 1.98.0-nightly`, release profile. `oqs-sys` built from vendored source
(`vendor/oqs-sys`) with two local build fixes for libclang 22 — see the comment in
`benches/comparison/Cargo.toml`.

| Operation    | `sntrup` (this crate) | PQClean (clean C) | liboqs (AVX2 dispatch) |
|--------------|------------------------|--------------------|-------------------------|
| keypair      | 473.3 µs               | 4718.4 µs          | **142.1 µs**            |
| encapsulate  | 35.1 µs                | 255.3 µs           | **12.4 µs**             |
| decapsulate  | 55.9 µs                | 646.8 µs           | **8.8 µs**              |

**The ARM-era claim "fastest of the three" does NOT transfer to x86_64.** This crate beats
PQClean's clean C by 10.0x / 7.3x / 11.6x — but on x86_64, liboqs runtime-dispatches to the
SUPERCOP AVX2 implementation (Toom/Karatsuba polynomial multiplication, optimized inversion),
a code path that simply does not exist on ARM, and wins every row by 3.3x / 2.8x / 6.3x.
Reaching parity requires the same algorithmic upgrades, not more schoolbook micro-tuning:
Karatsuba/Toom for the O(p²) multiplies and a faster (e.g. jump-divstep) inversion.

## What this session changed (all six parameter sets, measured on sntrup761)

Internal breakdown before → after, same core, `Instant`-probe over the crate's internals:

| Hot path            | before    | after     | Δ |
|---------------------|-----------|-----------|---|
| `rq::reciprocal3`   | 811.9 µs  | 315.3 µs  | **−61%** |
| `r3::reciprocal`    | 216.7 µs  | 72.1 µs   | **−67%** |
| `rq::mult`          | 12.5 µs   | 12.6 µs   | flat |
| `r3::mult`          | 13.2 µs   | 13.0 µs   | flat |

Criterion, end-to-end keypair: **1068.7 µs → 473.3 µs (2.26x, change −55.7%, p = 0.00)**.
Encapsulate/decapsulate unchanged (their cost is `rq::mult`, which didn't move — see dead
ends). Four changes landed, in order of impact:

1. **Overlapped final block in `minus_product_shift` kernels.** The backward-iterating SIMD
   loops always stranded `(n-2) mod width` bottom elements — 15 (i16) / 31 (i8) scalar
   reductions per call, two calls per loop iteration, ~1,500 iterations per inversion. Since
   higher blocks only write indices above the bottom region, one final full-width block at
   `start = 0` covers the remainder and recomputes the single overlap element to an identical
   value. Biggest single win for `r3::reciprocal` (169 → 72 µs at that point).
2. **16-bit signed-Montgomery `minus_product_shift` (rq, AVX2).** Replaced the widen-to-i32 +
   two-step Barrett chain (five `vpmulld` per 8 elements) with Seiler-style signed Montgomery
   in i16 lanes: `c' = c·2^16 mod± q` hoisted per call, then three 16-bit multiplies per 16
   lanes plus one branchless compare-and-correct (the quotient is provably in {−1,0,1}).
   rq inversion 601 → 381 µs at that point (−37%).
3. **Public-counter support window for `u`/`v`.** After iteration `i` the support of `u`/`v`
   is confined to `0..=i+1` (induction: `v` starts as {0}, each shift grows it by one, swaps
   only exchange the two). Processing `min(i+2, len)` elements — a bound that depends only on
   the public loop counter, never secrets — halves the u/v-side work. rq 812 → 633 µs.
4. **SIMD-width buffer padding in both inversions.** All f/g/u/v buffers rounded up to the
   widest SIMD block so no call enters its scalar tail; padding lanes provably stay zero
   (u/v) or only ever propagate upward past index p (f/g).

Also fixed: `p - 1 - i + jlo` in the row-major mult kernels underflows `usize` for `i ≥ p`
in **debug builds** (release wrapped back to the correct pointer, so benches/KATs passed).
On real x86 hardware every debug-mode SIMD test failed; reordered to `p - 1 + jlo - i`,
which never underflows. The Rosetta validation had been run in release mode only.

## Dead ends this round (measured, kept or reverted as noted)

- **AVX-VNNI (`vpdpwssd`) mult kernels**: fuses the `vpmaddwd` + `vpaddd` pair, but measured
  flat on Zen 5 — the kernel is load-bound (two 256-bit loads per MAC cap it at one MAC/cycle
  regardless of fusion). Kept (macro-generated alongside the AVX2 kernel, runtime-dispatched,
  differentially tested): zero cost here, and plausibly helps add-port-starved cores.
- AVX-512: not attempted for the mult kernels — Strix Point double-pumps 512-bit ops through
  a 256-bit datapath, so zmm width alone adds nothing the load ports can feed.

## Guardrail reminder

Same as the ARM round: validate SIMD changes with `--features kem,serde,std` (SIMD active)
AND `--features kem,serde,std,force-scalar` separately, in BOTH debug and release — the
debug-only underflow above hid for an entire investigation because differential tests ran
release-only under Rosetta.

---

# x86_64 round 2 (2026-08-03, gap-closing campaign)

Same machine and pinning as the previous section, **no concurrent load** this time.

| Operation    | `sntrup` | vs round 1 | PQClean | liboqs | gap to liboqs |
|--------------|----------|------------|---------|--------|----------------|
| keypair      | **360.8 µs** | 473.3 → −24% | 4544.8 µs | 107.8 µs | 3.3× |
| encapsulate  | **29.1 µs**  | 35.1 → −17% | 237.0 µs  | 11.4 µs  | 2.6× |
| decapsulate  | **54.7 µs**  | 55.9 → −2%  | 608.0 µs  | 8.3 µs   | 6.6× |

Cumulative since the campaign began: keypair **1068.7 → 360.8 µs (2.96×)**, encapsulate
34.3 → 29.1 µs, decapsulate flat. Lead over PQClean now 12.6× / 8.1× / 11.1×. Decapsulate
was explicitly re-measured after the shared-freeze changes: no regression (−2%, within noise).

## Correctness bug found and fixed: non-canonical `freeze`

The round-2 differential test for the fused kernel exposed that `modq::freeze`'s two-step
Barrett reduction emits values up to **±3 outside the canonical range** for a few thousand
inputs per parameter set (exhaustively scanned; all six sets affected; zero residues are
unaffected). A non-canonical coefficient wraps negative in `rq_encode`'s `+ q12` bias and
corrupts the variable-radix encoding — i.e. rare invalid public keys / ciphertexts, and a
latent x86-vs-scalar determinism split once the Montgomery kernel (strictly canonical)
landed. Fixed with a branchless final correction in scalar `freeze` and in every mult-kernel
vectorized freeze (AVX2 **and NEON** — the one deliberate ARM touch, required so all paths
produce byte-identical output). A `freeze_loose` without the correction survives only inside
`modq::reciprocal`'s serial square-multiply chain, where intermediates are residue-correct,
zero maps to literal 0, and everything escaping passes a later strict freeze (audited).
Pinned by an exhaustive-range regression test that fails against the old freeze at 2,675
inputs for q=4621 alone.

## What landed (each measured via the per-stage probe)

1. **Fused `minus_product_shift` + conditional swap** (rq and r3, AVX2): one memory pass
   instead of two per inversion iteration; the swap mask is derived from a scalar-computed
   post-shift leading coefficient. rq inversion 364 → 327 µs (A/B), r3 72 → 58 µs.
2. **Loose freeze in the reciprocal chain**: recovered the strict-freeze latency added to the
   ~20-freeze serial Fermat chain per iteration. rq inversion 327 → 283 µs.
3. **vpshufb mod-3 fixup LUT** in the r3 fused kernel (add + in-register shuffle replaces the
   6-op compare/mask chain).
4. **Vectorized small-stride sort passes** (p ∈ {1,2,4}) in `zx::sort`: register-local
   permute/min/max/blend for the p-passes, masked two-load blocks for small-p × large-q
   subpasses. `random_tsmall` 10.8 → 6.5 µs; encapsulate 32.6 → 29.0 µs. Overlapping-store
   shapes ((2,2,4), (1,1,2), (1,1,4)) stay scalar by design.
5. Guard fix: the overlapped bottom block in all shift kernels is only valid when `n` is a
   multiple of the vector width; now enforced (production callers always pass padded
   multiples — the new odd-length differential tests exposed the latent contract violation).

Cato (GPT-5.4, read-only cross-vendor audit): **PASS** — independently verified constant-time
discipline, the freeze_loose scoping, the overlap keep-mask lanes, and sort comparator
equivalence.

## Remaining gap and roadmap

The remaining 2.6–6.6× to liboqs is algorithmic, not micro-architectural:

- **Batched-row mult** (next, incremental): in each half of the row-major schoolbook, one
  operand's window is shared across adjacent rows (`jlo` or the g-offset pins to a constant),
  so batching 4 rows shares those loads (~2× load-traffic cut) and amortizes the per-row
  horizontal reduction (~23k cycles of the kernel's ~63k). Estimated 12.4 → ~8-9 µs.
- **NTT multiply + divstep inversions** (the real liboqs parity path — source-verified
  2026-08-03 by reading the vendored `pqclean_sntrup761_avx2` tree; the earlier
  "Karatsuba/Toom" guess was wrong). liboqs's x86 mult is Good's trick (768 → 3×512 via
  mask permutations) + two 512-point NTTs over the NTT-friendly primes 7681/10753 (4591
  itself is not NTT-friendly), 16-bit Montgomery pointwise stage, inverse NTTs, CRT
  recombination back to mod 4591 — O(n log n) vs our O(n²), ≈2-3 µs vs our 12.3 µs per
  mult. Its R/q inversion is Bernstein-Yang divstep with NO per-iteration division (the
  cross-multiply `g' = (f0·g − g0·f)/x` on a reversed input replaces our ~20-freeze Fermat
  quotient chain per iteration) plus publicly-scheduled shrinking windows in the second
  half; its R/3 inversion is fully bitsliced (two bitplanes, 256 coefficients per register
  pair). Port priority by measured impact: (1) divstep R/q inversion (~220 lines, keygen
  283 → ~70 µs est.), (2) NTT mult (~2200 lines with tables, helps every op — decap most),
  (3) bitsliced R/3 inversion, (4) codec vectorization (division-free mulhi/mullo radix
  trees, two-limbs-per-32-bit-lane encode combines, overlapping-tail loops). Caveat: the
  SUPERCOP code is per-parameter-set generated (761-specific NTT tables and radix chains);
  our crate serves six parameter sets from one generic path, so the port must either
  generate per-set tables or accept 761-only specialization first.

---

# x86_64 round 3 (2026-08-03): divstep R/q inversion ported

First item of the parity roadmap landed: `rq::reciprocal3` now runs the Bernstein–Yang
divstep inversion (ported from SUPERCOP's `crypto_core_invsntrup761`, generalized over all
six parameter sets) on x86_64/AVX2. The old top-coefficient-elimination algorithm remains
the non-x86/force-scalar path — and serves as the differential oracle: the port produces
**byte-identical output** for every parameter set (random + edge patterns).

| Operation | before | after | liboqs | gap |
|-----------|--------|-------|--------|-----|
| keypair | 360.8 µs | **158.7 µs** (−56.0%, p = 0.00) | 107.8 µs | **1.47×** |

Cumulative since campaign start: **1068.7 → 158.7 µs = 6.7×**. Encapsulate/decapsulate are
unaffected (they never invert).

Why it's so much faster than the old inversion: the loop has **no division** — the old form
computed a quotient via a ~20-freeze serial Fermat chain every one of 1523 iterations; the
divstep cross-multiply `g' = (f0·g − g0·f)/x` (on reversed inputs, so `/x` is a shift-down)
needs two 16-lane Montgomery products per block and nothing else. The second phase's f/g
windows also shrink by one per iteration on a public schedule.

Port notes (deviations from the C, all deliberate):
- Generic over q: both `f0` and `g0` are strictly frozen every iteration (the C skips the
  f0 freeze for q ≤ 5167); the value-magnitude fixpoint `B = q/(1 − hq/2^15)` stays under
  9k for q = 7879, far inside both i16 and the signed-Montgomery input bound.
- Buffer rule `ppad = 1 + ceil16(p)` (the C's 769 for p = 761): the 16-wide passes
  deliberately overrun `len`; every op is lanewise so overrun lanes never contaminate the
  true window.
- The invertibility byte is dropped: R/q is a field for these parameter sets, matching the
  old implementation's documented contract.
- Montgomery 2⁻¹⁶ factors cancel because each divstep scales a complete row of the
  transition matrix and the output is the same-row ratio `v/f0` (with 1/3 folded into r's
  initialization) — verified empirically by the byte-identical differential.

Remaining keypair gap to liboqs (~51 µs): `r3::reciprocal` 58 µs (theirs is bitsliced —
next roadmap item), mult 12.4 µs (NTT), codecs.

---

# x86_64 round 4 (2026-08-03): bitsliced R/3 inversion ported

Second roadmap item landed: `r3::reciprocal` now runs the bitsliced GF(3) divstep (ported
from SUPERCOP's `crypto_core_inv3sntrup761`, generalized over all six parameter sets) on
x86_64/AVX2, in `src/r3/bitsliced.rs`. Ternary coefficients live in two bitplanes, 256 per
register — the whole polynomial is 3-5 registers per plane and each divstep iteration is a
handful of 256-bit boolean ops, no multiplies. The elimination form remains the
non-x86/force-scalar path and the differential oracle (masks + values byte-identical, all
six sets, singular inputs included — first-run pass).

| Operation | before | after | liboqs | gap |
|-----------|--------|-------|--------|-----|
| keypair | 158.7 µs | **133.7 µs** (−15.6%, p = 0.00) | 106.6 µs | **1.25×** |

Cumulative since campaign start: **1068.7 → 133.7 µs = 8.0×**.

Generalization notes: the C's five hand-unrolled phases are two public per-iteration width
schedules — V/R grows one coefficient per iteration (`min(numvec, k/256 + 1)`) and F/G
shrinks with the remaining iteration count (`ceil((2p−1−k)/256)`, the divstep degree-sum
invariant); both reproduce the reference's p = 761 phase boundaries exactly. The magic
`F0[2]`/`F1[2]` init constants are just coefficients p−1, p in the interleaved bit order,
built generically through the same bit-transpose used for inputs.

Remaining keypair delta (~27 µs): mult 12.4 µs (NTT pending — also the whole remaining
encap/decap story), residual r3/divstep overhead vs their hand-unrolled code, codecs.

---

# x86_64 round 5 (2026-08-03): NTT multiply ported (p = 761)

The endgame item: `src/rq/ntt.rs` implements the dual-prime NTT multiply from SUPERCOP's
`crypto_core_multsntrup761` + its generated `_ntt` kernels — Good's trick (768 → 3 tracks of
512), 512-point NTTs over 7681 and 10753, a Karatsuba-shaped 3×3 pointwise stage, inverse
NTTs, and CRT back to mod 4591. The mod-3 multiply (`r3::mult`) reuses the same machine
single-prime (product coefficients ≤ p ≪ 7681/2, so no CRT). Both are differentially
verified against the schoolbook kernels — random and extreme inputs, exact match.

| Operation | before | after | PQClean | liboqs | gap |
|-----------|--------|-------|---------|--------|-----|
| keypair | 133.7 µs | **137.0 µs** | 4536.9 µs | 107.0 µs | 1.28× |
| encapsulate | 29.1 µs | **19.8 µs** (−32%) | 236.7 µs | 11.2 µs | 1.76× |
| decapsulate | 54.7 µs | **25.1 µs** (−54%) | 604.8 µs | 8.3 µs | 3.03× |

Campaign totals: keypair 1068.7 → 137.0 (7.8×), encapsulate 34.3 → 19.8 (1.7×), decapsulate
56.5 → 25.1 (2.3×). Versus PQClean: **33× / 12× / 24×**.

Notes and honest caveats:
- **Keypair did not improve** (133.7 → 137.0, and it uses only one multiply). The NTT's
  fixed overhead — two full 512-point transform pairs plus Good/ungood permutation passes —
  is comparable to a single 12 µs schoolbook multiply at p = 761. The win is concentrated
  where multiplies are repeated: decapsulate (three) and encapsulate.
- **p = 761 only.** The 3×512 Good machine holds products up to 1536 coefficients (2p−1 =
  1521 fits). p = 653 fits the same machine and needs only its own mod-q constants; p ≥ 857
  needs the Good factor-5 variant (5×512 = 2560) with a 5×5 pointwise stage — the twiddle
  tables are prime-specific, not p-specific, so they carry over unchanged. Everything else
  keeps the schoolbook kernels, which remain differentially tested.
- The `ntt512`/`invntt512` kernels are mechanical translations of auto-generated reference
  code (~840 lines each); the twiddle tables are extracted verbatim. They are *not*
  hand-written and should be regenerated, not hand-edited, if the reference changes.

Remaining gap is now dominated by the codecs and hashing (`rq_decode` ~4.8 µs, `rounded_*`
~4.7 µs, three SHA-512 calls) plus the NTT's own constant factor versus their hand-tuned
schedule.

---

# ARM round 1 (2026-08-03): divstep R/q inversion ported to NEON

The first of the three algorithmic wins carried back to ARM. `rq::reciprocal3` now dispatches
to the divstep inversion on aarch64 as well as x86_64; the elimination form remains the
force-scalar path and the differential oracle. Two NEON kernels in `src/rq/vector.rs`
(`swapeliminate_neon`, `xswapeliminate_neon`) mirror the AVX2 pair eight lanes at a time.

NEON has no single signed `mulhi`, so the Montgomery high half is `vmull_s16` +
`vmull_high_s16` + `vuzp2q_s16` (take the odd i16 halves) — three instructions, exact. The
conditional swap is `vbslq_s16`. Everything else transliterates.

**Verification (this is an x86 development machine — see the caveat below):**

- Cross-compiled `aarch64-unknown-linux-gnu`: clean under `clippy -D warnings`.
- **Cross-architecture KAT under QEMU:** a harness generates deterministic keypairs for all
  six parameter sets and hashes pk/sk; run natively and under `qemu-aarch64-static`, the
  outputs are **byte-identical**. Since x86 and ARM now run different inversion kernels, this
  is a genuine cross-implementation differential.
- **Mutation-tested:** deliberately corrupting the NEON kernel makes the KAT diverge, and
  restoring it makes it match again — proving the harness exercises the new code rather than
  a cached build.

Reproduce (needs `rustup target add aarch64-unknown-linux-musl` and `qemu-aarch64-static`;
link with `rust-lld`, since the host `ld.bfd` rejects aarch64 flags):

```
cargo build --release --target aarch64-unknown-linux-musl   # in a no-dev-deps harness crate
qemu-aarch64-static target/aarch64-unknown-linux-musl/release/<harness>
```

`cargo test --target aarch64-*` does **not** work here: a dev-dependency of `criterion`
compiles C and needs a cross gcc that this immutable host lacks. Hence the separate harness.

**Caveat — no ARM performance measurement.** Correctness is verified; speed is not. QEMU
timings are meaningless for this purpose. On x86 this same change took keypair 360.8 → 158.7
µs (2.3×); the ARM path should see a similar-shaped win because the eliminated work (a
~20-freeze Fermat quotient chain per iteration, ×1523 iterations) is architecture-independent
— **but that must be confirmed on real hardware before any claim is published.**

---

# x86_64 profile after the ports (2026-08-03) — where the remaining gap actually is

Re-profiled with all four ports live (both inversions divstep-class, both multiplies NTT).
The bottleneck has moved completely: **the multiplies are no longer significant** (12.3 → 2.6
µs for `rq::mult`, 12.3 → 1.3 for `r3::mult`), and the codecs now dominate.

| Stage (sntrup761) | µs | appears in |
|---|---|---|
| `rq::reciprocal3` | 90.5 | keygen |
| `r3::reciprocal` | 19.4 | keygen |
| `rq_decode` | 5.03 | encap, decap |
| `rounded_decode` | 4.98 | decap |
| `sort_uint32` (inside `random_tsmall`) | 5.06 | keygen, encap |
| `rq::mult` | 2.62 | all |
| `rounded_encode` | 1.45 | encap, decap |
| `r3::mult` | 1.30 | decap |
| hashes (3×) | ~3.1 | encap, decap |

Totals: keygen 121.8 (liboqs 107.0, **1.14×**), encapsulate 18.8 (11.2, **1.68×**),
decapsulate 24.3 (8.3, **2.9×**).

**The next target is the variable-radix decoders** — 10 µs of decapsulate's 24.3 (41%) and 5
µs of encapsulate. Ours is scalar with a `uint32_divmod_uint14` per pair; liboqs's is a fully
vectorized division-free radix tree.

**The enabling discovery for that work:** the moduli are *uniform within each level*, so the
per-level division is by a constant and therefore vectorizable. Measured chain for 761x4591:

| level | n | modulus in pairs | bottom bytes |
|---|---|---|---|
| 0 | 761 | 4591 (uniform) | 2 |
| 1 | 381 | 322 (uniform) | 1 |
| 2 | 191 | 406 (uniform) | 1 |
| 3+ | ≤96 | 2 distinct values | — |

Levels 0–2 hold 668 of ~760 total pairs (88% of the work) at a single constant modulus each.
Vectorizing just those three levels should capture most of the win; levels 3+ are small enough
to leave scalar. `combined` reaches ~21M at level 0, so the divide wants 32-bit lanes
(`_mm256_mul_epu32` even/odd passes) or liboqs's 16-bit `mulhi`/`mullo` formulation.

## Attempts this round that did NOT pay (measured, reverted)

- **Caching the bottom-byte count** (`while cm >= 16384`) from the decoder's forward pass
  instead of recomputing it in the backward pass: no measurable change — LLVM was already
  hoisting it. Reverted.
- **Batching `random_tsmall`'s RNG** into one `fill_bytes` instead of 761 `random()` calls:
  6.04 → 5.84 µs, within run-to-run noise. Reverted. Useful negative result: the cost is the
  **sort** (5.06 of the 6.18 µs), not RNG call overhead — so the sorting network is the target
  there, not the generator. (The change was KAT-verified not to alter the deterministic
  keypair byte stream, which is the hazard to watch if it is revisited.)

---

# x86_64 round 6 (2026-08-03): variable-radix decoders vectorized

Executed the plan from the previous section. `decode_level_avx2` in `src/rq/encoding.rs`
expands one decode level eight pairs at a time when all its full pairs share a modulus and
bottom-byte count — true for the wide levels of every parameter set, and where 88% of the
pairs live. Levels with mixed moduli, and the eight lowest pairs of every level, stay scalar.

| Operation | before | after | liboqs | gap (was) |
|-----------|--------|-------|--------|-----------|
| keypair | 137.0 µs | **126.9 µs** (−7.3%, p = 0.00) | 107.0 µs | **1.19×** (1.28) |
| encapsulate | 19.8 µs | **16.9 µs** (−15%) | 11.2 µs | **1.51×** (1.76) |
| decapsulate | 25.1 µs | **20.9 µs** (−17%) | 8.3 µs | **2.53×** (3.03) |

Campaign totals: keypair 1068.7 → 126.9 (**8.4×**), encapsulate 34.3 → 16.9 (2.0×),
decapsulate 56.5 → 20.9 (2.7×). Versus PQClean: **36× / 14× / 29×**.

Implementation notes:
- With a uniform bottom-byte count the byte cursor becomes the closed form
  `start + i·bb`, which is what makes a block kernel possible at all — the scalar loop
  threads `bpos` sequentially.
- `combined` reaches ~21M at level 0, so the divide runs in 32-bit lanes. AVX2 multiplies
  only even 32-bit lanes, so `(x · v) >> 31` is done as two `_mm256_mul_epu32` passes (even
  lanes, then lanes shifted down 32) reblended — the standard divide-by-constant pattern.
  Both Barrett steps and the speculative correction are replicated lanewise from
  `uint32_divmod_uint14`, so the SIMD and scalar paths agree bit-for-bit.
- **The bug worth recording:** when `n` is odd the unpaired tail element must be copied
  *before* the kernel runs. The scalar loop visits it first (highest index), but the kernel's
  stores reach `out[2·n_full − 1]` and clobber it. Caught immediately by the round-trip tests
  across all six parameter sets.

Verified: all four test configurations (SIMD/force-scalar × debug/release), clippy clean on
x86 and aarch64, fmt clean, and both KATs unchanged — x86 identical to before the change, ARM
still byte-identical to x86.

Remaining decapsulate gap (~12.6 µs over liboqs): the two decoders still cost ~3-4 µs after
vectorization (levels 3+ and the scalar prologues), plus `sort_uint32` 5.06 µs, three SHA-512
calls ~3.1 µs, and the NTT's constant factor.

---

# x86_64 round 7 (2026-08-03): NTT buffer copies removed; sort deferred

| Operation | before | after | liboqs | gap |
|-----------|--------|-------|--------|-----|
| keypair | 126.9 µs | **125.1 µs** | 107.0 µs | 1.17× |
| encapsulate | 16.9 µs | **17.0 µs** (flat) | 11.2 µs | 1.51× |
| decapsulate | 20.9 µs | **20.4 µs** | 8.3 µs | 2.47× |

**Landed:** `mult768`'s per-prime pass was staging Good's three tracks into separate arrays
and then copying them into a contiguous batch buffer for `ntt512`, and copying the result
back — about 12 KB of memcpy per multiply. `good`/`ungood` now write straight into the
contiguous 6×512 layout the batched NTT already wanted. Small but real: keypair −1.5%,
decapsulate −2.3%, encapsulate flat.

*Measurement note:* the first bench run showed a 2–3% **regression** on keypair/encapsulate
with p < 0.05; a second run showed −4%/−1.4%. Code-layout shifts of this size are noise on
this machine, and single criterion runs with significant p-values can still mislead. Absolute
means across runs are the numbers reported above.

**Sort: attempted, deliberately not landed.** `sort_uint32` is still 5.06 µs and remains the
largest single item in keygen and encapsulate. Its remaining scalar work is exactly three
comparator shapes — `(p=2, off=2→4)`, `(p=1, off=1→2)`, `(p=1, off=1→4)` — where the two
8-lane windows overlap, so the two-load/two-store form clobbers itself. Fixing them properly
needs djb's approach: load a 16-lane window, bring partners into alignment with a constant
permute, min/max, permute back, single store. A first attempt at a cheaper masked form turned
into something that would have been slower than the scalar code, and was reverted rather than
committed. This is the next well-scoped task; the three shapes above are the complete list.

**Floor note on decapsulate:** ~3.1 µs of its 20.4 is three SHA-512 calls through the shared
`sha2` crate. That is not reachable by tuning this crate's code, so decapsulate parity with
liboqs is not achievable by SIMD work alone — roughly 15% of the remaining gap is hash cost.

---

# x86_64 round 8 (2026-08-03): sort transpose attempt — corrected diagnosis, no change landed

Implemented the masked-store kernel for the three overlapping comparator shapes identified
last round, measured it, and **reverted it: the sort stayed at 5.07 µs, identical to before.**
`vpmaskmovd` stores are multi-uop on Zen 5, so trading the scalar loop for masked stores is a
wash. An earlier variant that also replaced the *already-vectorized* register-local path with
the same general kernel measured 5.9% **worse** on encapsulate — the specialized one-load /
one-store path is meaningfully better than a general two-load / two-masked-store one.

**The previous round's diagnosis was wrong, and this is the useful output of this round.**
The three scalar shapes were never the problem. Counting comparators for n = 761:

| where | comparators | share |
|---|---|---|
| passes with `p >= 8` (well vectorized, 8/8 lanes useful) | 8007 | 47% |
| passes with `p < 8` (vectorized but only 4/8 lanes useful) | 8755 | **52%** |

So more than half the work runs at **50% lane efficiency**: for `p ∈ {1,2,4}` only the lanes
with `l & p == 0` are active, and the rest of each vector is wasted. Chasing the last few
scalar shapes could never have fixed that — they are a rounding error next to the lane waste.

**What would actually fix it** is djb's structure: rather than optimizing each small-stride
pass in place, transpose the array into registers once and run *all* remaining stages
(`p = 4, 2, 1` and their sub-passes — 27 of the 55 passes) entirely in-register at full lane
utilization, then transpose back. That is a restructure of `sort_avx2`, not a per-pass fix,
and it is the correct scope for the next attempt. Expected ceiling: roughly halving the 5 µs,
which is ~2.5 µs off keygen and encapsulate each.

Net code change this round: **zero.** Both attempts measured and reverted.

---

# x86_64 round 9 (2026-08-04): decapsulate itemized; scale3/freeze3 vectorized

Profiled decapsulate stage by stage rather than guessing (last round's lesson). The itemization
for sntrup761, decapsulate total 20.05 µs:

| stage | µs | note |
|---|---|---|
| `rq::mult` ×2 | 4.98 | NTT |
| `rounded_decode` | 2.90 | levels 3+ still scalar |
| `rq_decode(pk)` | 2.83 | same |
| **`t3` scale-by-3 + lift-to-R3 loop** | **1.86** | **fully scalar — fixed this round** |
| `rounded_encode` | 1.43 | |
| `hash_session` | 1.42 | `sha2`, not reachable |
| `r3::mult` | 1.24 | NTT |
| `hash_confirm` | 0.37 | |
| everything else | <0.5 | |
| unaccounted (≈10 heap allocations per call) | ~2.4 | see below |

**Landed:** `rq::scale3_freeze3` replaces the scalar loop that computed
`mod3::freeze(modq::freeze(3·cf[i]))` per coefficient. The AVX2 form does eight coefficients
per iteration, replicating `modq::freeze`'s two Barrett steps plus the strict-canonical
correction and then `mod3::freeze`'s two steps lanewise, so it agrees with the scalar path
exactly (differential test over all six parameter sets, random plus canonical extremes).

| Operation | before | after | liboqs | gap |
|-----------|--------|-------|--------|-----|
| keypair | 125.1 µs | 126.2 µs (noise) | 107.0 | 1.18× |
| encapsulate | 16.9 µs | 17.1 µs (noise) | 11.2 | 1.53× |
| decapsulate | 20.4 µs | **19.6 µs** (−7.2%, p = 0.00) | 8.3 | **2.37×** |

Isolated stage measurement: decapsulate 20.05 → 18.28 µs on the probe harness, i.e. the full
1.8 µs the stage cost. The end-to-end bench shows a smaller delta because it includes
allocation and RNG noise; both numbers are reported rather than the flattering one.

## What is left in decapsulate, ranked

1. **`rq::mult` ×2 at 4.98 µs.** liboqs runs the same algorithm and its *entire* decapsulation
   is 8.3 µs, so its multiply must be ≈1.5 µs against our 2.49. The gap is NTT scheduling, not
   algorithm — their kernel is hand-tuned; ours is a mechanical translation.
2. **The two decoders at 5.73 µs combined.** Levels 0-2 are vectorized; levels 3+ (94 pairs)
   and each level's 8-pair prologue are still scalar, and the forward pass recomputes the
   modulus chain on every call even though it is constant per parameter set. Caching that
   chain is the obvious next step and needs no SIMD.
3. **≈2.4 µs of heap traffic** — `decapsulate_inner` performs about ten `Vec` allocations per
   call (f, ginv, c, cf, t3, r, r_enc, h, hr, cnew). A single reusable scratch buffer would
   remove nearly all of it. This is a plain refactor with no numerical risk and is probably
   the best effort-to-reward item remaining.
4. **~1.8 µs of SHA-512** — outside this crate.

---

# Post-merge (2026-08-04): rebased onto `hardening` + CI-gate commits

Our optimization work was rebased onto the pulled commits. Two files conflicted (`src/r3.rs`,
`src/rq.rs`) because the remote's `hardening` commit independently applied **the same
`p - 1 + jlo - i` underflow fix** to the multiply kernels, in regions we had since
macro-wrapped. Resolved in favour of our restructured code, then the remote's zeroization was
ported into it by hand — including into the code paths the remote never saw (`rq::ntt`,
`r3::bitsliced`, `reciprocal3_divstep`), whose scratch buffers hold secret-derived
intermediates for exactly the same reason.

Correctness after merge: all four test configurations green, clippy clean on x86_64 and
aarch64, fmt clean, and both KATs unchanged — x86 output identical to pre-merge, ARM still
byte-identical to x86.

**The hardening is not free.** Zeroization is volatile and cannot be optimized away.

The first post-merge measurement was taken while a video call was running, so it was re-run on
an idle machine. Comparing the two runs exposed a measurement problem worth fixing: **liboqs,
whose code did not change at all, moved +2.1% between them.** That is the run-to-run drift
floor on this machine, and it means comparing raw microseconds across runs overstates or
understates changes by roughly that much.

The fix is to quote the ratio against liboqs measured *in the same run*, which cancels
whole-machine drift:

| Operation | pre-merge | post-merge (quiet) | regression |
|-----------|-----------|--------------------|------------|
| keypair | 1.18× | **1.22×** | +3.3% |
| encapsulate | 1.53× | **1.62×** | +5.9% |
| decapsulate | 2.37× | **2.61×** | +10.1% |

Absolute means from the quiet run: keypair 133.1 µs (liboqs 109.2), encapsulate 18.5 (11.4),
decapsulate 21.6 (8.3). Versus PQClean: 34× / 13× / 28×.

The earlier call-contaminated run reported the regressions as +2.5% / +9.0% / +15.3% from raw
absolutes. Normalised, they are +3.3% / +5.9% / +10.1% — so the decapsulate cost was
overstated by about a third, but **the regression is real and material**, not an artifact.

*Methodology note for future rounds: report the same-run ratio against an unchanged reference,
not deltas between absolute means from different runs. Single criterion `change:` verdicts
across runs are unreliable at this magnitude even when they carry p < 0.05.*

**Open question for the maintainer.** The zeroization is currently applied at the *outer*
buffers of the NTT path but not to the transform's internal working buffers (`prime_pass`'s
6×512 batch and the inverse-NTT scratch), which hold the same secret-derived data. There are
three coherent positions and they should be chosen deliberately rather than drifting:

1. **Wipe everything**, accepting a further slowdown on top of the 15%.
2. **Keep the current boundary** — wipe what crosses function boundaries, accept that
   transform internals live briefly on one frame.
3. **Wipe nothing in the NTT path**, recovering the ~3 µs, on the argument that these are
   short-lived stack frames immediately reused.

This is a security-policy call, not a performance one, so it is left as-is (option 2) pending
a decision.

---

# x86_64 round 10 (2026-08-04): zeroize cost recovered without weakening it

The hardening regression was not the wiping — it was the *granularity* of the wiping.
`Zeroize` on a slice issues one volatile store **per element**, and the compiler is not
permitted to merge or vectorize volatile stores. Across the multi-kilobyte SIMD scratch
buffers that meant thousands of 2-byte stores per call.

Isolating it: disabling the NTT wipes entirely moved decapsulation from 2.61× to 2.22×, so
the wiping cost 0.39 ratio points — about 18% of the operation.

`src/wipe.rs` now re-views a buffer as `[u64]` before zeroizing, wiping any unaligned head and
tail at their own width. **The volatile guarantee is identical** — every byte is still written
through a volatile store, and the trailing fence is unchanged — but a quarter as many stores
are issued for `i16` data and an eighth for `i8`. All wipe sites route through it: the NTT
multiplies, both inversions (divstep and elimination), the schoolbook kernels, and the
bitsliced module's byte planes and bitplane registers.

| Operation | pre-merge | post-merge (element-wise) | **now (u64-width)** |
|-----------|-----------|---------------------------|---------------------|
| keypair | 1.18× | 1.22× | **1.18×** |
| encapsulate | 1.53× | 1.62× | **1.58×** |
| decapsulate | 2.37× | 2.61× | **2.27×** |

Absolutes: keypair 127.6 µs (liboqs 108.2), encapsulate 18.2 (11.6), decapsulate 19.8 (8.7).

Keypair is fully back to its pre-merge ratio and decapsulation is now **better** than
pre-merge, despite carrying zeroization the pre-merge tree did not have at all. Encapsulate
retains about 3% — just above this machine's ~2% noise floor.

Nothing was given up to get this: the wiping still covers every buffer it covered before,
including the paths the remote's commit never saw. Verified with all four test
configurations, clippy clean on x86_64 and aarch64, and both KATs unchanged — x86 output
identical to pre-merge, ARM still byte-identical to x86.
