# Comparison benchmark results

This file is an append-only engineering log: every optimization that landed, with the
measurement that justified it, and every idea that was tried and *rejected* with the
measurement that killed it. It is long because the dead ends are the valuable part — they are
what stops the same idea being retried.

## Where things stand

sntrup761 on x86_64 (AMD Ryzen AI 9 HX 370, Zen 5), against liboqs's AVX2 build and
PQClean's C reference:

| Operation | sntrup | liboqs | PQClean |
|-----------|-------:|-------:|--------:|
| keypair | 106.6 µs | 107.9 µs (0.99x) | 4545.7 µs (42.7x) |
| encapsulate | 10.5 µs | 11.5 µs (0.91x) | 239.1 µs (22.9x) |
| decapsulate | 8.4 µs | 8.4 µs (1.00x) | 607.0 µs (72.6x) |

On aarch64 (Apple M2 Max) against their portable C builds (2026-08-05, after the divstep
port and the encapsulation-key cache): keypair 2.6x, encapsulate 19%, decapsulate 19%. We
are ahead on every operation on both architectures while also zeroizing every secret-derived
scratch buffer, which neither C reference does.

## Reading this file

Sections run oldest to newest. The aarch64 run at the top is the original baseline; the
numbered x86_64 rounds that follow are this crate's x86 optimization campaign, each one
stating what was measured, what changed, and what was verified.

## Method notes worth reusing

- **Same-run ratios only.** Machine state drifts; compare implementations measured in the
  same `cargo bench` invocation, never across runs.
- **Establish the noise floor first.** For sub-2% changes, Criterion's variance is too wide.
  A/B on fixed-iteration cycle counts under `perf stat -r 3`, and run the *same binary* twice
  first to see what "no change" actually looks like (0.6–0.8% on this machine).
- **Profile, do not infer.** Two conclusions in this log were reached by subtracting assumed
  costs and both were wrong. Every attribution here that matters was taken from `perf` on
  both implementations.
- **`--all-features` enables `force-scalar`**, which silently compiles the SIMD kernels out of
  the test binary. Verify SIMD with a feature set that leaves it off.

---

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

---

# x86_64 round 11 (2026-08-04): allocation-free hot paths

The top-ranked item from the round-9 decapsulate itemization: encapsulation and decapsulation
performed a dozen-plus heap allocations per call (working buffers, plus each codec rebuilding
its constant moduli vector on the heap). All hot-path codecs now have `_into` variants
writing into caller buffers with stack scratch bounded by `MAX_P`, and
`decapsulate_inner`/`create_cipher` run entirely on stack frames — **zero heap allocation in
decapsulation**, one remaining in encapsulation (the returned ciphertext itself). Secret
scratch is still wiped, now as whole frames (padding included) through the fast `wipe`.

| Operation | before | after | liboqs | gap (was) |
|-----------|--------|-------|--------|-----------|
| keypair | 127.6 µs | **125.5** | 107.7 | 1.16× (1.18) |
| encapsulate | 18.2 µs | **17.3** | 11.3 | 1.53× (1.58) |
| decapsulate | 19.8 µs | **17.3** (−12.5%) | 8.4 | **2.07×** (2.27) |

The round-9 estimate attributed ~2.4 µs of decapsulate to allocation churn; the measured win
is 2.5 µs. This is also the first structural change that is fully architecture-neutral —
the ARM path gets it as-is (KAT-verified byte-identical under QEMU).

The now-unused allocating wrappers (`rq_decode`, `rounded_encode`, `rounded_decode`,
`zx::decode`) were removed per the no-dead-code rule; `rq_encode` and `zx::encode` remain in
use on the keygen path.

Campaign standing after eleven rounds: keypair **8.5×** (1068.7 → 125.5), encapsulate
**2.0×** (34.3 → 17.3), decapsulate **3.3×** (56.5 → 17.3). Versus PQClean: 36× / 14× / 35×.
Versus liboqs: 1.16× / 1.53× / 2.07× — with ~1.4 µs of the decapsulate gap being SHA-512
outside this crate.

---

# x86_64 round 12 (2026-08-04): decode plan cached

The decoders rebuilt their moduli tree, per-level bottom-byte counts and level offsets on
every call, even though those depend only on the (public, fixed) starting modulus and `p`.
Isolated cost: **0.751 µs per decode** — 1.5 µs of each decapsulation, which runs two.

`DecodePlan` is now built once per `(modulus, length)` pair and reused. There are exactly
twelve live combinations (six parameter sets × {Rq, rounded}), so a fixed twelve-slot
`OnceLock` table covers them with no locking on the hot path and no per-call work. A lazy
table was chosen over compile-time constants deliberately: const tables for all twelve chains
would add roughly 42 KB of static data to the binary for the same runtime win.

The cached `all_bb` also removes the `while cm >= 16384` recomputation from both the scalar
backward pass and the SIMD level kernel — the same caching that measured as *no change* in
round 8 when it was recomputed per call, because LLVM was hoisting it within a single decode
but could not hoist it across calls.

| Operation | before | after | liboqs | gap (was) |
|-----------|--------|-------|--------|-----------|
| keypair | 127.0 µs | **128.1** | 109.7 | **1.17×** (1.16) |
| encapsulate | 17.5 µs | **16.8** | 11.4 | **1.47×** (1.53) |
| decapsulate | 17.3 µs | **15.7** (−9.2%) | 8.3 | **1.89×** (2.07) |

Measured on an idle machine (`/proc/pressure/cpu` at zero; the load average was still decaying
from earlier work, which is stale history rather than live contention — pressure is the
reliable signal). liboqs landed within ~1% of its historical values, so this run supersedes the
contended ranges reported when this section was first written.

Versus PQClean: **35× / 14× / 39×**. Campaign totals: keypair **8.3×** (1068.7 → 128.1),
encapsulate **2.0×** (34.3 → 16.8), decapsulate **3.6×** (56.5 → 15.7).

Verified: four test configurations, clippy clean on x86_64 (both feature sets) and aarch64,
fmt clean, x86 KAT unchanged, ARM KAT byte-identical to x86.

---

# x86_64 round 13 (2026-08-05): djb's sort ported — the lane-waste finding acted on

`src/zx/djbsort.rs` is a full port of the reference `crypto_sort_int32`, replacing the Batcher
network on x86_64/AVX2. The round-8 census said 52% of our comparators ran at half lane
utilisation and that no per-pass fix could reach it; this is the structural change that does.
The old network is kept as the fallback for other targets and as the differential oracle.

Measured in isolation at p = 761: **5.23 µs → 0.68 µs, a 7.6× speedup** (8.5× at n = 1024).
That is far beyond the ~2× the census predicted — the per-pass structure was also paying
memory traffic across 55 passes, not just wasting lanes.

| Operation | before | after | liboqs | gap (was) |
|-----------|--------|-------|--------|-----------|
| keypair | 128.1 µs | **120.5** | 108.3 | **1.11×** (1.17) |
| encapsulate | 16.8 µs | **12.7** (−25%) | 11.4 | **1.11×** (1.47) |
| decapsulate | 15.7 µs | 15.8 (no sort in decap) | 8.4 | 1.87× |

**Encapsulation and keypair are now within 11% of liboqs.** Campaign totals: keypair **8.9×**
(1068.7 → 120.5), encapsulate **2.7×** (34.3 → 12.7), decapsulate **3.6×** (56.5 → 15.7).

Porting notes, in case this is revisited:
- What made it tractable was building it undispatched with a differential test, then wiring it
  in only once every length passed. The tree stayed green throughout a ~1,200-line port.
- Two real bugs, both caught by tests rather than review. First, `n - 4*q - j` and friends go
  *negative* in the C, where signed arithmetic makes `minmax_vector` a no-op; in Rust that
  underflows `usize`. Saturating subtraction reproduces the intent exactly. Second, and more
  subtle: the reference's `goto continue16` / `goto continue8` jump **into the middle** of the
  following `if` blocks, past their `j = 0`, so `j` carries across. Restructuring those as
  ordinary sequential blocks silently reset `j` and produced arrays that were sorted except for
  one lost element — which only showed up from n = 273 upward.
- The `n == 8` network is descending-only and ignores its direction flag; that is the
  reference's documented precondition, not an omission. Determined by probing rather than
  assuming, after a test failure that turned out to be the test's fault.

Verified: four test configurations, clippy clean on x86_64 (both feature sets) and aarch64,
fmt clean, and both KATs unchanged — x86 output identical to before, ARM still byte-identical
to x86. A KAT that does not move while the sorting algorithm underneath is swapped wholesale
is the strongest evidence available here.

---

# x86_64 round 14 (2026-08-05): decapsulation itemised again — where its floor is

Decapsulation is the last operation above 1.2× (1.87×), so it was re-itemised after the three
optimisations landed since round 9. Current breakdown for sntrup761, total 15.7 µs:

| stage | µs | share |
|---|---|---|
| `rq::mult` ×2 | 5.10 | 33% |
| `rounded_decode` + `rq_decode` | 4.21 | 27% |
| SHA-512 (`hash_session` + `hash_confirm`) | 1.70 | 11% |
| `rounded_encode` | 1.36 | 9% |
| `r3::mult` | 1.34 | 9% |
| `scale3_freeze3`, `round3`, codecs, weight mask | 0.79 | 5% |

**The NTT multiply is at its floor and is not the lever it looks like.** Instrumenting inside
`mult768`: `good` ×2 = 0.141 µs, `ntt512(6)` = 0.408, `invntt512(3)` = 0.232, `ungood` = 0.131,
pointwise + CRT ≈ 0.55, summing to the observed 2.376 µs. A 512-point NTT over 16-wide lanes
needs roughly 288 vector butterflies × 9 layers; at ~1150 instructions per transform the six
batched forward transforms have a floor near 0.33 µs against the 0.408 measured. There is no
2× hiding in there — the earlier inference that liboqs's multiply must be ~1.3 µs was derived
by subtracting *assumed* costs for its other stages, and is not sound. Its advantage is more
likely spread across its codecs and its own SHA-512.

Both prime passes are genuinely required: `rq::mult` multiplies a mod-q operand (|f| ≤ 2295)
by a ternary one, so product coefficients reach 761 × 2295 ≈ 1.75M and a single 7681 or 10753
modulus cannot represent them. `r3::mult` already exploits the single-prime shortcut.

## Attempted and reverted: relaxing the decoder's uniformity requirement

The decoder vectorises only levels whose full pairs all share a modulus. Levels 3 and up miss
that by exactly one pair — the last, which inherits the propagated odd-tail modulus — so
relaxing "all pairs uniform" to "a uniform prefix" looked like it would bring ~104 more pairs
per decode into the kernel, worth an estimated 0.6 µs per decode.

**It is not sound in that form, and the reason is worth recording.** The kernel's stores reach
`out[2·n_uniform + 14]`. Any pair *above* the uniform prefix still needs to read its own
`out[i]`, and for `n_uniform ≤ i < 2·n_uniform` that input has already been overwritten. The
all-scalar version is correct only because it runs strictly descending: pair `i` is read before
pair `i/2` (processed later) overwrites it. Batching the middle range breaks that invariant.

Reordering into three phases — scalar above the prefix, then the kernel, then scalar below —
is the right shape, but the byte-cursor threading has to be split to match it, and two attempts
at that still failed the round-trip tests. Reverted rather than shipped; the tree is back to
the measured 1.88× with a note in the code at the uniformity check.

**Also worth noting:** a first "revert" left the scalar loop walking all ~760 pairs with a
`continue` rather than only the low range, which cost 1 µs (15.7 → 16.7). Restoring the tight
bound brought it back. Loop *shape* matters as much as loop *body* here.

Net code change this round: none. Verified: four test configurations, clippy clean on x86_64
(both feature sets) and aarch64, fmt clean, both KATs unchanged.

---

# x86_64 round 15 (2026-08-05): public key decoded once per key, not once per call

Decapsulation re-encrypts against the public key embedded in the secret key, and was decoding
it on **every call** — 2.07 µs of identical work each time, 13% of the operation.
`DecapsulationKey` now decodes it once into a `OnceLock` and reuses it.

| Operation | before | after | liboqs | gap (was) |
|-----------|--------|-------|--------|-----------|
| keypair | 124.0 µs | 124.0 | 108.3 | 1.14× |
| encapsulate | 12.5 µs | 12.5 | 11.5 | 1.09× |
| decapsulate | 15.8 µs | **13.7** (−13.2%) | 8.5 | **1.62×** (1.88) |

Notes on what this does and does not claim:
- The saving lands on the *second and later* decapsulations with a given key. A single
  decapsulation with a fresh key pays the same cost as before — the work is moved, not removed.
  For the common server pattern (one long-lived key, many ciphertexts) it is a straight win, and
  that is also what the benchmark measures.
- This is an API-shape advantage rather than a better algorithm: liboqs's C entry point takes
  raw secret-key bytes and has nowhere to keep a decoded form, so it must redo this work. Our
  typed key can hold it. Worth being explicit that the comparison is no longer strictly
  like-for-like on this stage.
- The cached value is the **public** key, so it needs no zeroization; the hand-written
  `Zeroize` impl for `DecapsulationKey` is unchanged and still wipes the secret bytes.
- `DecapsulationKey` grew by `2p` bytes (1522 for sntrup761, against a 1763-byte key).
  Construction, `TryFrom`, serde deserialization and `Clone` all route through one constructor
  so the cache can never be stale or missing.

Campaign totals: keypair **8.6×** (1068.7 → 124.0), encapsulate **2.7×** (34.3 → 12.5),
decapsulate **4.1×** (56.5 → 13.7). Versus PQClean: 37× / 19× / 44×.

Verified: four test configurations, clippy clean on x86_64 (both feature sets) and aarch64,
fmt clean, both KATs unchanged.

## Remaining decapsulation budget (13.7 µs)

| item | µs | tractable? |
|---|---|---|
| `rq::mult` ×2 | 5.10 | no — measured at its floor (round 14) |
| `rounded_decode` | 2.14 | partly — needs the three-phase restructure |
| SHA-512 ×3 | 1.70 | not in this crate |
| `rounded_encode` | 1.36 | possibly avoidable, but see below |
| `r3::mult` | 1.34 | no — same NTT floor |

One idea deliberately **not** pursued: `rounded_encode` exists only so the re-encrypted
candidate can be compared against the received ciphertext as bytes. Comparing coefficients
instead would save its 1.36 µs — but the byte comparison is what rejects non-canonical
encodings of the same coefficients, which is load-bearing for CCA security. Not worth trading
for 9%.

---

# Where parity stands, and what it would take (2026-08-05)

| Operation | sntrup | liboqs | ratio | absolute gap |
|-----------|--------|--------|-------|--------------|
| keypair | 123.0 µs | 109.1 | 1.13× | 13.9 µs |
| encapsulate | 12.6 µs | 11.5 | **1.09×** | 1.0 µs |
| decapsulate | 13.8 µs | 8.5 | 1.63× | 5.3 µs |

**Encapsulation is at parity for practical purposes** — 1.0 µs on 12.6, close to this machine's
measurement noise across runs.

**Keypair (13.9 µs) is one function.** Itemised after all the ports landed:
`rq::reciprocal3` is **86.6 µs of 118 — 73%**; `r3::reciprocal` 19.9; everything else under 3 µs
combined. The divstep kernel runs ~293 cycles per iteration against a ~240-cycle instruction
floor, i.e. about 60% of peak issue rate. A manual 2× unroll to expose more ILP made it
*slower* (86.6 → 89.1 µs) — the compiler is already scheduling it well and the extra register
pressure cost more than the pipelining gained. Reverted. One known genuine difference remains:
the reference skips the `f0` freeze when `q <= 5167`, which we always perform for genericity,
worth roughly 0.6 µs at p = 761.

**Decapsulation (5.3 µs) does not reconcile, and that is the honest finding.** Our components
sum to about 13 of the measured 13.8: two `rq::mult` at 5.10, two decoders at 4.21, three
SHA-512 at 1.70, `rounded_encode` 1.36, `r3::mult` 1.34. liboqs performs the *same* three NTT
multiplies. If its multiplies cost what ours do (6.44 µs combined), only ~2.0 µs would remain
in its 8.48 µs total for all codecs plus three SHA-512 calls — which is not possible. So one of
these must be true, and the measurements here cannot distinguish them:

1. its NTT multiply is materially faster than ours, contradicting the round-14 finding that our
   `ntt512` sits near its instruction floor; or
2. its codecs and SHA-512 are much faster than ours, concentrating the difference outside the
   multiply.

Settling it requires profiling the liboqs binary itself, which this host cannot do — `perf` is
not installed and the relevant functions are `static`, so they are not callable from a
harness. That is the next concrete step for anyone continuing: get a profiler onto a machine
with this benchmark and attribute liboqs's 8.48 µs directly rather than by subtraction. The
earlier "their multiply must be ~1.3 µs" claim was exactly that kind of subtraction and was
withdrawn in round 14; this section deliberately does not repeat the mistake.

Campaign totals: keypair **8.7×**, encapsulate **2.7×**, decapsulate **4.1×** faster than the
starting point; 37× / 19× / 44× against PQClean.

---

# The decapsulation gap, finally measured (2026-08-05)

`perf` became available, so liboqs's decapsulation was profiled directly instead of inferred.
Percentages from a 300k-iteration run pinned to one core, converted against its 8.48 µs total:

| liboqs symbol | share | µs | our equivalent | µs |
|---|---|---|---|---|
| `crypto_hashblocks_sha512_c` | 31.0% | 2.63 | `sha2` crate (AVX2) | **1.70** |
| `ntt512` + `invntt512` + `crypto_core_mult` + `good`/`ungood` | 52.7% | 4.47 | our two `rq::mult` | 5.10 |
| `crypto_core_mult3` | 5.2% | 0.44 | our `r3::mult` | 1.34 |
| `crypto_decode_761x1531` | 1.55% | **0.13** | `rounded_decode` | **2.14** |
| `crypto_decode_761x4591` | 1.58% | **0.13** | `rq_decode` | (now cached) |
| `crypto_encode_761x1531round` | 1.72% | **0.15** | `rounded_encode` | **1.36** |

**Two of my working assumptions were wrong, in opposite directions.**

First, **our hashing is faster than theirs, not slower.** liboqs uses a plain C SHA-512
(`crypto_hashblocks_sha512_c`) and it is the single largest item in its decapsulation at 31%.
The `sha2` crate's AVX2 backend beats it by 0.93 µs. Every earlier note treating SHA-512 as
"1.7 µs we can't reach" had it backwards — it is 0.9 µs we are already winning.

Second, **their variable-radix codecs are 9-16× faster than ours**, and that is where the gap
actually lives. Their `crypto_decode_761x1531` runs in 0.13 µs against our 2.14 µs for the same
job; their `crypto_encode_761x1531round` is 0.15 µs against our 1.36 µs. These are the
auto-generated, fully-vectorized, division-free radix trees described earlier — vectorized at
*every* level, where ours vectorizes only the levels whose moduli happen to be uniform and
leaves the rest scalar.

Reconciling the 5.3 µs gap:

| component | delta | note |
|---|---|---|
| codecs | **+3.09 µs** | the real target |
| multiplies | +1.53 µs | we are ~24% slower; round 14's "near the floor" was roughly right |
| SHA-512 | **−0.93 µs** | we are ahead |
| remainder | +1.67 µs | glue, copies, weight mask, verify |
| **total** | **+5.36 µs** | matches the measured 5.3 µs |

**So the next step is unambiguous: port the generated codecs.** `crypto_decode_761x1531`,
`crypto_decode_761x4591` and `crypto_encode_761x1531round` are auto-generated like the NTT
kernels were, so they should transpile mechanically rather than needing the hand-porting the
sort required. Expected recovery is roughly 3 µs of decapsulation (13.8 → ~10.8, ratio 1.63× →
~1.28×), plus a smaller win in encapsulation which also encodes and decodes.

This supersedes the round-14 speculation and the "cannot distinguish" conclusion of the
previous section. The lesson is cheap to state: one profiler run answered in minutes what three
rounds of subtraction-based inference got wrong twice.

---

# x86_64 round 18 (2026-08-05): generated decoder ported

Acting on the profile: `crypto_decode_761x1531` is now ported into
`src/rq/codec761.rs` and dispatched for p = 761. It is a mechanical translation
of generated C, vectorized at every radix level, where the generic
implementation only vectorizes levels whose moduli happen to be uniform.

| Operation | before | after | liboqs | gap (was) |
|-----------|--------|-------|--------|-----------|
| keypair | 123.0 µs | 123.6 | 107.7 | 1.15× |
| encapsulate | 12.6 µs | 12.4 | 11.3 | 1.10× |
| decapsulate | 13.8 µs | **11.6** (−15.8%) | 8.3 | **1.40×** (1.63) |

`rounded_decode` was 2.14 µs and the reference's equivalent 0.13 µs; the saving
landed as predicted. The differential test compares the port against the generic
decoder on random, all-zero, all-`0xff` and sparse byte strings — it passed first
run, and adversarial (non-canonical) inputs matter here because decapsulation
must handle attacker-chosen ciphertexts, not just well-formed ones.

Notes:
- The module carries deliberate module-scoped `allow`s for sign-losing and
  truncating casts. Those casts *are* the algorithm — they reproduce C's
  `int16` wrapping, which the radix decomposition depends on. The comment at the
  top says so, and says not to copy the pattern into hand-written code.
- Like `rq::ntt`, this is p = 761 only. Every other parameter set keeps the
  generic codec, which is also the differential oracle.

**Not done: `crypto_encode_761x1531round`** (ours 1.36 µs, theirs 0.15 µs, so
~1.2 µs still on the table). Unlike the decoder it walks three pointers with
mid-loop decrements and mixes u16/u32 widths, so it needs hand-porting rather
than the transpiler. That is the next concrete step, and would put decapsulation
near 10.4 µs (~1.25×).

Campaign totals: keypair **8.6×**, encapsulate **2.8×**, decapsulate **4.9×**
against the starting point.

---

# x86_64 round 19 (2026-08-05): generated encoder ported — encapsulation overtakes liboqs

`crypto_encode_761x1531round` is now ported alongside the decoder. It needed
hand-porting rather than transpiling (three pointers walked with mid-loop
back-off, mixed u16/u32 widths), but its six loops reduce to two shapes, so they
are factored into two parameterized helpers instead of six transcriptions.

| Operation | before | after | liboqs | ratio |
|-----------|--------|-------|--------|-------|
| keypair | 123.6 µs | 120.7 | 108.5 | 1.11× |
| encapsulate | 12.4 µs | **11.1** | 11.4 | **0.97× — faster** |
| decapsulate | 11.6 µs | **10.2** | 8.4 | **1.21×** |

**Encapsulation is now faster than liboqs**, and decapsulation has gone 1.63× →
1.21× across the two codec ports. Against PQClean: 38× / 21× / 60×.

Two things this port turned up:

- **The reference fuses rounding into the encoder** (`..._round`), taking
  un-rounded coefficients, whereas our generic encoder expects input `round3`
  has already processed. The first differential run failed for exactly this
  reason — the port was correct and the test was comparing different contracts.
  A new `round_and_encode_into` entry point owns the distinction, so both call
  sites in `create_cipher` and `decapsulate_inner` no longer call `round3`
  separately on the p = 761 path.
- **The last four radix levels are scalar in the reference** and easy to miss:
  after the vector passes the first 987 of 1007 bytes matched and the tail was
  zeros, which is what pointed at them.

Campaign totals: keypair **8.9×**, encapsulate **3.1×**, decapsulate **5.6×**
against the starting point.

## Standing gap

Only keypair (12.2 µs) and decapsulate (1.8 µs) remain. Keypair is 73% a single
function — `rq::reciprocal3` at ~86 µs — and manual unrolling there has already
been tried and measured slower. Decapsulate's residue is the ~1.5 µs multiply
difference plus glue; note our SHA-512 is already 0.9 µs *ahead* of theirs.

---

# x86_64 round 20 (2026-08-05): keypair profiled both sides — the inversions are already at parity

`perf` on both implementations, converted against each one's measured total:

| | ours | liboqs |
|---|---|---|
| R/q inversion | 89.4 µs (74.1%) | 82.6 µs (76.1%) |
| R/3 inversion | 19.8 µs (16.4%) | 20.0 µs (18.4%) |
| everything else | ~8.6 µs | ~5.9 µs |

**Keypair is 93% inversions on our side, and both inversions are essentially at
liboqs's level** — R/3 is a dead heat, R/q is 8% behind. The 12 µs keypair gap is
therefore ~6.8 µs of R/q inversion and ~2.7 µs spread across encode, RNG and
multiply. There is no large structural win here of the kind the codecs offered.

**Attempted and reverted: ascending traversal in `xswapeliminate`.** The profile
showed that pass costing 34.7% against 27.9% for `swapeliminate`, despite both
doing an identical 54.6k blocks — the only structural difference being that it
walks descending (the `v` store is shifted up by one, so ascending would clobber
the next block's first input). Carrying that input in a register makes an
ascending version possible, and the prefetcher should prefer it.

It measured **143.4 µs against 120.7** — 19% worse. The per-iteration branch and
the loop-carried register dependency cost far more than any prefetch benefit, and
the reference's descending choice is vindicated. The kernel now carries a comment
recording the measurement so the idea is not retried.

Net code change this round: none. Standing: keypair 120.8 µs (1.11×),
encapsulate 11.1 (0.97×, faster), decapsulate 10.2 (1.21×).

---

# x86_64 round 21 (2026-08-05): the small-poly codec and a collapsed `scale3`

Re-profiling decapsulation after the round-19 codec port showed the gap had
moved somewhere unexpected. Against each side's own measured total:

| | ours (10.15 µs) | liboqs (8.4 µs) | |
|---|---|---|---|
| SHA-512 | 1.59 | 2.40 | *we are 0.8 µs faster* |
| NTT stack | 6.19 | 5.14 | |
| `x3` small-poly decode | **0.357** | **0.013** | 27x |
| `x3` small-poly encode | **0.161** | **0.006** | 27x |
| `scale3` | **0.335** | **0.029** | 11x |
| `memset` | 0.58 | — | |

0.85 µs — half the entire decap gap — sat in three routines that between them
touch about 190 bytes. They had never shown up before because the codecs and
inversions dominated everything until they were fixed.

## `crypto_{en,de}code_761x3` — AVX2 (`src/zx/codec3.rs`)

Both were plain scalar loops over `chunks(4)`. The packing is four trits per
byte, so:

- **Encode** is two multiply-accumulates. `maddubs` folds adjacent trits as
  `t0 + 4·t1` (max 10, nowhere near the 16-bit accumulator), then `madd` folds
  those pairs as `x0 + 16·x1` — which is exactly the packed byte. A shuffle
  gathers byte 0 of each 32-bit lane. 32 trits → 8 bytes per iteration.
- **Decode** replicates each input byte across a 32-bit lane, so the four trits
  live at shifts 0/2/4/6 *of that lane*. AVX2 has no per-byte variable shift,
  but shifting the whole lane by each amount and byte-blending the one that
  lands correctly costs three shifts and three blends. 8 bytes → 32 trits.

Differential-tested against the scalar form at every real
`small_encode_size - 1`, at every length 0..24 so the tail runs in all residues,
and over all 256 byte values.

## `scale3` — the composition collapses to a threshold

This one is not a vectorization win, it is an algebraic one. `scale3_freeze3`
computes `mod3::freeze(modq::freeze(3c))`. Write `s = 3c − kq` for the `k` that
centers `s`. **Every parameter set has `q ≡ 1 (mod 3)`** — 4591, 4621, 5167,
6343, 7177, 7879 all are — so `s ≡ −k (mod 3)`. The output depends only on `k`;
`c mod 3` cannot reach it at all. And `|3c| ≤ 1.5(q−1)` bounds `k` to
`{−1, 0, 1}`, so `k` is just the sign of `c` outside a dead zone of half-width
`ceil((q+1)/6)`.

Two Barrett reductions, a canonical correction and two more Barrett steps — in
32-bit lanes, 8 coefficients at a time — become two `cmpgt`s and a subtract in
16-bit lanes, 32 coefficients at a time.

The scalar path was deliberately **left as the literal composition**. That is
what makes it an independent oracle: `scale3_freeze3_matches_scalar` now checks
the identity on every run, and `scale3_collapses_to_a_threshold_on_c` proves it
exhaustively over every representable `c` for all six parameter sets.

## Result

| | before | after | vs liboqs |
|---|---|---|---|
| keypair | 120.76 | **118.65** | 1.11x → **1.09x** |
| encapsulate | 11.11 | **10.89** | 0.97x → **0.96x** |
| decapsulate | 10.15 | **9.18** | 1.21x → **1.09x** |

Decapsulation is 9.6% faster and all three operations are now within 9% of
liboqs, with encapsulation ahead of it. Both routines have dropped below 1% of
the decap profile entirely.

## Known remaining item: 5.9% of decap is `memset`

`__memset_avx512` is 5.9% of our decapsulation and liboqs has no equivalent.
Callers: the NTT's `fg`/`hpad`/`h7681`/`h10753` scratch (3.3%) and
`decapsulate_inner`'s `MAX_P`-sized stack frames (1.0%) — about 61 KB zeroed per
decap. **Every one of those buffers is provably written in full before it is
read** (`good` covers all 1536 slots, the pointwise loop covers all 1536,
`ungood` fills its output), so the zeroing is pure dead store.

`#[inline]` on `good`/`ungood` to let LLVM see the full overwrite and dead-store-
eliminate it **did not work** — memset stayed at 5.9%. (`#[inline(always)]` is
rejected outright alongside `#[target_feature]`.) Removing it needs
`MaybeUninit`, i.e. uninitialized-memory `unsafe`, which is a different and
subtler risk class than the SIMD intrinsics already in the crate and which
`CLAUDE.md` requires prior approval for. Worth roughly 0.5 µs on decap (→ ~1.03x)
and smaller amounts on the other two operations. **Not done — flagged for a
decision.**

---

# x86_64 round 22 (2026-08-05): removing the scratch zero-fill

The `memset` item flagged at the end of round 21, approved and done.

## What was actually being paid for

Roughly 61 KB zeroed per decapsulation, in two groups:

- **NTT scratch** (3.3% of decap) — `fg` (6 KB), `hpad`, `h7681`, `h10753` in
  `mult768`/`mult768_3`, plus `fp`/`gp`/`fg`/`out` in `mult761`/`mult3_761`.
- **`decapsulate_inner` and `create_cipher` frames** (1.0%) — ten `MAX_P`-sized
  stack arrays of which only `..p` is ever touched.

Every one is written in full before it is read, so the zero-fill is a dead
store — but the producers are opaque `#[target_feature]` calls, so LLVM cannot
prove the overwrite and cannot eliminate it. Worse, these buffers are *also*
wiped on the way out, so each was being traversed twice.

## `src/scratch.rs`

`MaybeUninit` scratch, with the write-before-read obligation **machine-checked
rather than merely documented**: debug builds fill the buffer with `0x5A5A`
(23130 — outside every coefficient range in the crate, verified against the
parameter sets by a test) instead of leaving it indeterminate. A producer that
skips an element then yields visibly wrong output in the differential and KAT
suites. Release builds skip the fill, which is the point. The whole test matrix
includes debug configurations, so every run exercises the check.

Two spellings, deliberately: `uninit_scratch!` carries its own `unsafe` block for
callers in safe code, while the SIMD kernels — already inside one — call
`scratch::uninit` directly rather than nest redundantly. Each site carries a
`SAFETY:` comment naming the routine that fills it.

## Two buffers were not safe to convert as-is

`gp[761..768]` in both multiplies, and `fp[761..768]` in `mult3_761`, are written
only over `0..P` but read over all 768 — the zero padding is what makes the
transform's zero-extension correct. They were silently depending on the
initializer. Those tails are now cleared explicitly, which is the honest
statement of the requirement either way.

## Result

| | round 21 | round 22 | vs liboqs |
|---|---|---|---|
| keypair | 118.65 | 118.97 | 1.09x → 1.10x (noise) |
| encapsulate | 10.89 | **10.68** | 0.96x → **0.94x** |
| decapsulate | 9.18 | **8.89** | 1.09x → **1.06x** |

`memset` no longer appears in the decap profile at all. The decap gain is
0.29 µs against the ~0.5 µs estimated — the estimate assumed the traffic
vanished, but the exit wipe still touches the same memory, so only one of the two
passes was removed. Keypair is unmoved: at 119 µs dominated by inversions, 61 KB
of zeroing was never material there.

Standing: encapsulation is 6% faster than liboqs, decapsulation within 6%,
keypair within 10%.

---

# x86_64 round 23 (2026-08-05): the wipe width, and constant masks in Good's permutation

After round 22 the decapsulation gap was 0.51 µs and the profile said all of it —
and more — was the multiply. Our SHA-512 is 0.89 µs *ahead* of theirs and our
codecs 0.37 µs ahead; against that, `mult761` was 2.43 µs to their 1.55 and
`mult3_761` 0.64 to their 0.45.

## Wiping cost 0.21 µs, and PQClean pays none of it

Disabling the NTT scratch wipes as an experiment moved decap from 8.89 to 8.68.
That is a real security property the reference implementations simply do not
have, so the answer was not to drop it but to make it cheaper: `zeroize` issues
one volatile store *per element* and volatile stores cannot be merged, so the
existing `u64` view was still doing 768 stores per `mult761`.

`wipe` now uses 32-byte volatile stores over the aligned interior on x86_64,
with the `u64` form kept as the portable floor and the unaligned head and tail
still wiped at their own width. That recovered essentially the whole 0.21 µs.
Tested at every offset and length across an alignment period, including that
nothing outside the slice is touched, and cross-checked against the `u64` path.

**decap 8.89 → 8.69 (1.06x → 1.03x)**, encap 10.68 → 10.65.

## `mask()` was a load, six to nine times per block

`good` and `ungood` select one of three lane masks by an index that depends on
the block number, so `mask(t)` compiled to a memory load — six per block in
`good`, nine in `ungood`.

The index can be made constant. Reindexing the track loop by `u = (t − b) mod 3`
turns `OR_t (T_t & M_{(t−b)%3})` into `OR_u (T_{(u+b)%3} & M_u)`: the masks
become compile-time constants that stay in registers, and the block-dependent
rotation moves onto the address, which is scalar arithmetic. In `good` the
rotation lands on the store address and the second operand's mask is always
`m[(u+1) % 3]`, because its block index is `b0 + 2 (mod 3)`.

Criterion could not resolve this against its own variance, so it was A/B'd on
fixed-iteration cycle counts under `perf stat -r 3`, with a same-binary
double-run first to establish a 0.6–0.8% noise floor:

| | constant masks | original | |
|---|---|---|---|
| decap | 8.560e9 | 8.679e9 | **−1.4%** |
| encap | 10.787e9 | 10.753e9 | +0.3% (noise) |
| keypair | 12.002e9 | 12.012e9 | −0.1% (noise) |

Kept: decapsulation runs three multiplies to encapsulation's one, so it sees the
most of it, and nothing regressed beyond noise.

## Standing

| | round 21 | round 23 | vs liboqs |
|---|---|---|---|
| keypair | 118.65 | 121.57 | 1.11x |
| encapsulate | 10.89 | **10.80** | **0.95x** |
| decapsulate | 9.18 | **8.61** | 1.09x → **1.03x** |

Decapsulation is within 3% of liboqs and encapsulation is 5% ahead of it. What
remains in decap is `mult761` and `mult3_761`; `ntt512` and `invntt512` are
already at parity (1.98 vs 1.93, and 1.19 vs 1.22 — we are ahead on the inverse).

---

# x86_64 round 24 (2026-08-05): AVX-512 for the divstep inversion — keypair overtakes liboqs

Neither PQClean nor liboqs has a 512-bit path for this KEM. Their sntrup761 is
AVX2 throughout; the `avx512` hits in the liboqs tree are BIKE. This box is a
Zen 5 with `avx512f/bw/vl/dq/vbmi/vnni`, and the divstep elimination passes are
~63% of key generation, so lane width was the largest untouched lever left.

## The port

`swapeliminate` and `xswapeliminate` map onto 512-bit almost verbatim — the
arithmetic is `mulhi`/`mullo`/`sub` on 16-bit lanes, all present in AVX-512BW.
The one improvement over a mechanical widening: `mask` is all-ones or all-zero,
so it maps directly onto a `__mmask32` and `_mm512_mask_blend_epi16` replaces
`_mm256_blendv_epi8` **without needing a broadcast vector constant at all**.

The padding invariant changed with it. `ppad` was `1 + p.next_multiple_of(16)`;
it is now 32. Padding to the widest kernel costs the narrower ones nothing,
because the extra lanes stay zero and **zero is a fixed point of the elimination
step** — they neither affect nor are affected by the result. That is the same
argument that already justified the 16-lane overrun.

Detection is `avx512f && avx512bw && avx512vl`, cached like the existing AVX2 and
AVX-VNNI probes, with the AVX2 kernels kept as the fallback for everything else.

## Result

| | round 23 | round 24 | vs liboqs |
|---|---|---|---|
| keypair | 121.57 | **107.81** | 1.11x → **0.99x** |
| encapsulate | 10.80 | **10.46** | 0.95x → **0.91x** |
| decapsulate | 8.61 | **8.46** | 1.03x → **1.01x** |

**Key generation is 11% faster and now beats liboqs.** The encapsulation and
decapsulation movement is code-layout noise — neither calls the inversion.

The keypair profile shifted as well as shrank: `xswapeliminate` went from 34.7%
to 41.0% of the total while `swapeliminate` fell from 27.9% to 23.2%, so the
Bezout-side pass gained less from the wider lanes. That is consistent with its
shape — it is the descending pass whose store is shifted up by one, so it has a
load/store dependency the other does not.

Next: `r3::bitsliced::reciprocal_divstep` is now 18.5% of key generation (~20 µs)
and is still 256-bit.

---

# Architecture coverage: what aarch64 does and does not get

The x86_64 campaign produced two kinds of result — algebraic findings, which are
architecture-neutral, and SIMD kernels, which are not. This is the honest split, because
"we optimized sntrup" should not be read as "aarch64 got all of it".

| Finding | On aarch64 today | Portable? |
|---|---|---|
| `scale3` collapses to a threshold | **No** — the identity is proven and used only in the AVX2 kernel; aarch64 runs the literal scalar composition | **Yes, and cheaply.** The algebra is architecture-neutral and already verified exhaustively for all six parameter sets. Needs only a ~6-instruction NEON kernel. Was 11x on x86 |
| `x3` small-poly codec | **No** — scalar | Yes: `maddubs`/`madd` map to `vmull`/`vpadd`; the decode spread maps to `vqtbl1q_u8` plus a shift vector. Was 27x on x86 |
| Uninitialized scratch | **Partially — yes.** The `decapsulate_inner`/`create_cipher` frames are shared code | The NTT scratch is inside the x86-only NTT module |
| Wider volatile wipe | **No** — takes the portable `u64` path | Yes: a 16-byte NEON volatile store is 2x the `u64` width |
| Constant masks in Good's permutation | **No** — inside the x86-only NTT | Not applicable; aarch64 does not use the NTT |
| **AVX-512 divstep** | **No** | **No.** NEON is fixed at 128 bits. An equivalent needs SVE2, which is not broadly available |
| Divstep inversion itself | **Yes** — ported to NEON earlier in the campaign | — |

So: of this round's work, aarch64 currently gets the shared-frame scratch change and nothing
else. The single highest-value follow-up is the `scale3` threshold — the hard part (proving
the identity) is done and architecture-independent, and only the kernel is missing.

Modules compiled on x86_64 only: `r3::bitsliced`, `rq::codec761`, `rq::ntt`, `zx::codec3`,
`zx::djbsort`.

---

# ARM round 2 (2026-08-05, Apple M2 Max): hardware confirmation, a latent NEON freeze bug, and the encapsulation-key cache

First run of the x86 campaign's work on real ARM silicon. Three findings.

**1. The divstep port's promised confirmation — delivered.** ARM round 1 shipped the NEON
divstep inversion verified only under QEMU and said the speed "must be confirmed on real
hardware before any claim is published." Confirmed: keypair 1341 → 695 µs (**1.9x**), against
the same-run C references at 1.82–1.88 ms — **2.6x faster than both**. The portable pieces of
the campaign carried too: decapsulate picked up the secret-key h-cache (84.5 → 72.2 µs) and
encapsulate the scratch/codec work (50.0 → 47.4 µs), before this round's own change below.

**2. A latent strict-freeze divergence in a NEON kernel, caught by the ported test suite.**
`rq/vector.rs`'s `minus_product_shift_neon` still used the loose two-step Barrett freeze; the
x86 campaign had made scalar `freeze` strictly canonical (± a-few-counts correction) and
updated every kernel it could run — but could not run the NEON ones, and the fused-cswap
differential test failed here on first execution (one lane off by exactly q, mask=0,
q=4621). Fix: the same two branchless correction steps every other freeze path now carries.
This is the second time a kernel-vs-reference differential test caught a divergence no
KAT/round-trip run had surfaced — the tests transfer across machines even when the
performance work cannot.

**3. Encapsulation-key cache — the mirror image of round-1's h-cache.** The secret key got a
decoded-polynomial cache on the x86 machine; the *encapsulation* key was still decoding the
public polynomial (`rq_decode`) and hashing it (Hash4(pk)) on every call, both per-key
constants. Same `OnceLock` pattern, both values public, no zeroization needed:
encapsulate 47.4 → 41.8 µs (**−12%**).

Where this machine stands after the round (same-run, Criterion means):

| Operation | sntrup | PQClean (clean C) | liboqs (clean C) |
|-----------|-------:|------------------:|-----------------:|
| keypair | **696.5 µs** | 1.819 ms (2.6x) | 1.879 ms (2.7x) |
| encapsulate | **41.8 µs** | 51.5 µs (1.23x) | 51.7 µs (1.24x) |
| decapsulate | **72.7 µs** | 90.2 µs (1.24x) | 90.6 µs (1.25x) |

Full sweep (`benches/mod.rs`): sntrup761 keygen 695 µs / encaps 42.1 µs / decaps 67.6 µs;
sntrup1277 keygen 1.88 ms / encaps 97.8 µs / decaps 181.1 µs. (The comparison harness's
decapsulate is ~5 µs above the sweep's because its keypair/ciphertext fixtures land colder
in cache; same-run ratios are the meaningful numbers.)

Housekeeping: the `[patch.crates-io]` vendored `oqs-sys` was in the x86 machine's tree but
never committed (75 MB — too heavy for the repo). Reconstructed here from the registry
package plus the documented build.rs tweak (`layout_tests(false)` for the sig header only),
and `benches/comparison/.gitignore` now ignores `vendor/` — each bench machine recreates it
the same way.

## What's left on ARM, in expected-value order

1. **Port the NTT multiply to NEON** — the big one. On x86 it took encapsulate −32% and
   decapsulate −54%; the ARM schoolbook multiply is ~24 µs of encapsulate's 42. The
   `ntt.rs` butterflies are AVX2-intrinsic-heavy (~360 intrinsic sites), so this is a real
   porting project, not a recompile — but the twiddle tables, Good's permutation, and the
   CRT recombination are architecture-independent and carry over unchanged.
2. **The constant-weight sampler** (`random_tsmall` + Batcher sort): ~15 µs of encapsulate,
   now its single largest component. The NEON sort processes 4 lanes per comparator pass
   where 16 are available, and the small-stride passes fall back to scalar; djbsort-class
   performance on this sorter would take several µs off encapsulate *and* keypair.
3. **Codec vectorization** (`rq_decode` / `rounded_*`): the x86 profile's post-NTT
   bottleneck. The variable-radix divmod chains are serial per level but lanes within a
   level are independent; whatever shape fixes it on x86 should port.
