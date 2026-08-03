# One complete run

**Machine:** Apple M2 Max, macOS (Darwin 25.5.0), native `aarch64-apple-darwin` — NEON is a
baseline guarantee of the architecture, so all three implementations below use their
NEON/portable-C paths; none of this run exercises AVX2 (x86_64-only).

**Toolchain:** `rustc 1.97.1`, `cargo 1.97.1`, release profile, default Cargo features for
every crate except `pqcrypto-ntruprime` (`avx2` feature left off — see the README).

**Command:** `cargo bench --manifest-path benches/comparison/Cargo.toml`

| Operation    | `sntrup` (this crate) | PQClean (clean C) | liboqs (clean C) |
|--------------|------------------------|--------------------|-------------------|
| keypair      | **1.359 ms**           | 1.822 ms           | 1.869 ms          |
| encapsulate  | 69.94 µs               | **53.64 µs**       | 53.36 µs          |
| decapsulate  | 133.83 µs              | 94.40 µs           | **92.93 µs**      |

Bold marks the fastest of the three per row. Each figure is Criterion's reported mean.

## Reading this

Key generation is dominated by rejection-sampling a weight-*w* ternary polynomial and an R/3
reciprocal computed via a `2p+1`-iteration Euclidean-style loop — the loop trip count, not the
polynomial multiply, sets its cost, and this crate's NEON-accelerated `swap`/`minus_product_shift`
primitives (used inside that loop) win there.

Encapsulate and decapsulate are dominated by the O(p²) schoolbook polynomial multiplies
(`rq::mult`, plus `r3::mult` on the decapsulate side). Starting point: encapsulate 1.86x slower
than PQClean, decapsulate 2.06x slower. Current: encapsulate **1.30x**, decapsulate **1.42x**.

### The investigation

An internal breakdown of `encapsulate` (`std::time::Instant` around each sub-step, sntrup761)
found `rq::mult` alone was **78 µs of a 99.8 µs total** at the start of this investigation — the
entire cost, effectively, since every other step (ternary generation, rounding, encoding,
hashing) was under 20 µs combined. That pointed the investigation squarely at the multiply, and
comparing this crate's `mult_neon`/`mult_avx2` against PQClean's reference C
(`crypto_core_multsntrup761.c`) and its disassembly turned up two real, verified fixes:

**Fix 1 — hoist a redundant conversion out of the hot loop.** `g` was being re-sign-extended
from i8 to i32 **inside** the outer loop, redone once per `f[j]` (761 times) instead of once
upfront — it doesn't depend on the loop variable. Cut `mult` from 77.9 µs to ~52 µs (**−33%**).

**Fix 2 — use NEON's widening multiply-accumulate instead of separate widen+multiply+add.**
Disassembling PQClean's *portable, scalar-looking* C (`objdump` on the object cc-rs produced)
showed clang's autovectorizer had generated `smlal`/`smlal2` — NEON's i16×i16→i32 widening MAC,
processing 8 lanes per 128-bit register. This crate's kernel stored `g` as i32 and used
`vmlaq_s32` (4 lanes/register): both `f` (Fq range) and `g` (ternary) fit comfortably in i16,
so there was no reason for the i32 storage. Switching `g` to i16 and using
`vmlal_n_s16`/`vmlal_high_n_s16` (i16 in, i32 accumulator, one instruction, 8 lanes) cut
`mult` further, to ~24 µs, and the same fix applied to `r3::mult` (16 lanes/register via
`vmlal_s8`/`vmlal_high_s8`, since ternary values fit in i8) shaved another ~12%
(28.4 µs → 25.1 µs) off it. These two fixes account for essentially the entire improvement.

**Dead ends** (implemented, measured, reverted — kept here so the next attempt doesn't re-walk
them):
- Fusing the multiply-add on the *original* i32 column-major kernel (`vmlaq_s32`) — no
  measurable change; that loop wasn't instruction-throughput bound.
- Two-batch ILP within the i32 column-major loop — measured *slightly worse*.
- Row-major with a single i32 accumulator per row (matching the reference's memory-access
  pattern: accumulate one output row in a register, write once) — measured **slower** (89.6 µs
  vs 51.4 µs for the i32 column-major baseline at the time): the per-row `vaddvq_s32` horizontal
  reduction, paid `2p-1 ≈ 1521` times, cost more than the memory traffic it removed.
- Row-major combining the i16 widening-MAC *and* two independent accumulator chains per row
  (closer to what clang's autovectorizer actually does — it uses four chains) — measured
  **statistically tied** with the i16 column-major version above. Once the widening-MAC fix
  closed most of the per-element cost, the memory-traffic difference between column-major and
  row-major stopped mattering at this array size (a few KB, comfortably L1-resident). Kept
  column-major for being the simpler of the two equally-fast options.
- Applying the same i16-storage idea to the AVX2 kernel — analyzed, not attempted. AVX2 has no
  single-instruction i16-widening multiply-accumulate (NEON's `vmlal`/`vmlal_high` has no direct
  AVX2 equivalent), so shrinking `g` to i16 there would trade fewer memory bytes for *more*
  instructions per element (an added `_mm256_cvtepi16_epi32` per 128 bits) — a net-negative
  trade by the same instruction-counting logic that correctly predicted fix 2's NEON win. Since
  this development machine can't measure real AVX2 hardware timing (only correctness, via
  cross-compilation under Rosetta, which doesn't reflect real performance), this wasn't guessed
  at further. AVX2 keeps fix 1 (the redundant-conversion hoist, which is unambiguously a
  removal of wasted work, not a trade-off) but not fix 2.

### What's still open

The remaining ~1.3-1.4x gap is real. PQClean's algorithm structure was confirmed identical to
this crate's (`kem.c`'s `crypto_kem_dec` does exactly two `Rq_mult_small` calls plus one
`R3_mult`, matching this crate's two `rq::mult` calls plus one `r3::mult` — no missing
algorithmic shortcut). The disassembly showed clang's autovectorized loop uses **four**
independent accumulator chains per row where this crate's best row-major attempt used two;
whether going to four (or more directly matching clang's exact unrolling) closes the rest of the
gap is untested — the two-chain version already reached parity with column-major, so this would
need to be measured, not assumed. Confirming exactly where the remaining cycles go needs a real
profiler (Instruments/`perf`), neither available in this environment; this investigation was
`Instant`-timing- and disassembly-driven, which was enough to find two large, unambiguous wins
but is a blunter instrument than a profiler for chasing the last ~30-40%.

## This crate's own sweep (native, NEON active, default features)

`cargo bench` (`benches/mod.rs`), same machine, current state:

| Parameter set | keygen    | encapsulate | decapsulate |
|----------------|-----------|-------------|-------------|
| sntrup761      | 1.355 ms  | 70.0 µs     | 133.8 µs    |
| sntrup1277     | 3.682 ms  | 162.6 µs    | 332.1 µs    |

Before this investigation: sntrup761 encapsulate 101.4 µs / decapsulate 196.1 µs; sntrup1277
encapsulate 252.7 µs / decapsulate 525.0 µs. ~30-37% faster across the board on both parameter
sets, all changes covered by the existing round-trip, KAT, and serde test suite (which caught
nothing — every fix and every reverted dead end passed the full suite; the dead ends were
correct code that was simply not faster).
