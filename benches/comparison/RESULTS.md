# One complete run

**Machine:** Apple M2 Max, macOS (Darwin 25.5.0), native `aarch64-apple-darwin` — NEON is a
baseline guarantee of the architecture, so all three implementations below use their
NEON/portable-C paths; none of this run exercises AVX2 (x86_64-only).

**Toolchain:** `rustc 1.97.1`, `cargo 1.97.1`, release profile, default Cargo features for
every crate except `pqcrypto-ntruprime` (`avx2` feature left off — see the README).

**Command:** `cargo bench --manifest-path benches/comparison/Cargo.toml`

| Operation    | `sntrup` (this crate) | PQClean (clean C) | liboqs (clean C) |
|--------------|------------------------|--------------------|-------------------|
| keypair      | **1.337 ms**           | 1.811 ms           | 1.872 ms          |
| encapsulate  | **45.42 µs**           | 53.14 µs           | 53.74 µs          |
| decapsulate  | **77.77 µs**           | 92.18 µs           | 93.77 µs          |

Bold marks the fastest of the three per row. Each figure is Criterion's reported mean. This
crate is now the fastest of the three on every operation: keypair by 26%, encapsulate by 15%,
decapsulate by 16%. At the start of this investigation it trailed the C references by 1.86x on
encapsulate and 2.06x on decapsulate.

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

## This crate's own sweep (native, NEON active, default features)

`cargo bench` (`benches/mod.rs`), same machine, current state:

| Parameter set | keygen    | encapsulate | decapsulate |
|----------------|-----------|-------------|-------------|
| sntrup761      | 1.340 ms  | 44.95 µs    | 76.09 µs    |
| sntrup1277     | 3.634 ms  | 102.7 µs    | 196.5 µs    |

At the start of the investigation: sntrup761 encapsulate 101.4 µs / decapsulate 196.1 µs;
sntrup1277 encapsulate 252.7 µs / decapsulate 525.0 µs. **2.26x / 2.58x faster** (761) and
**2.46x / 2.67x faster** (1277), every change bit-for-bit verified against the scalar
reference, the KAT vectors, and the round-trip/serde suites on both the NEON and forced-AVX2
paths.
