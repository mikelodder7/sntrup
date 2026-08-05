# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-05

### Added

- `kem` feature: implementations of the [`kem`](https://docs.rs/kem) crate's traits
  (`Kem`, `Encapsulate`, `Decapsulate`, `Generate`, `TryKeyInit`, `KeyExport`, …) for every
  parameter set, so Streamlined NTRU Prime drops into code written generically over KEMs.
  The traits and marker types are re-exported from `sntrup::kem`, so no direct dependency on
  a version-matched `kem` crate is needed. Runnable demo in `examples/kem_traits.rs`.
- Run-time SIMD dispatch from cached CPU-feature probes: AVX-512 (F/BW/VL), AVX2, and
  AVX-VNNI on x86_64; NEON on aarch64. A default `cargo build --release` now uses the widest
  available instruction set — previously the AVX2 kernels were compiled in only under
  explicit `RUSTFLAGS` and every ordinary build silently ran scalar code.
- `force-scalar` feature to compile out every SIMD kernel; the scalar paths produce
  bit-identical output and serve as the differential oracle.
- Permanent differential test suites pinning every SIMD kernel (and the NTT) to the scalar
  reference on random and extreme inputs across all six parameter sets, plus an
  all-lengths/all-patterns sweep for the constant-time sort.
- Declared and CI-enforced MSRV: `rust-version = "1.95"`.
- docs.rs now builds with the `kem`, `serde`, `std`, and `alloc` features enabled so the
  full API is visible in the rendered documentation.
- A standalone comparison benchmark harness (`benches/comparison`, not packaged) measuring
  this crate against PQClean (`pqcrypto-ntruprime`) and liboqs (`oqs`), with an append-only
  engineering log of every optimization and dead end in `benches/comparison/RESULTS.md`.

### Changed

- Large performance rework on both architectures; all figures are sntrup761 against
  references measured in the same run.
  - x86_64 (Zen 5): the polynomial multiply is a dual-prime NTT (Good's 3×512
    decomposition over 7681/10753, CRT recombination), both ring inversions use a
    vectorized divstep (AVX2/AVX-512), and the constant-time sort is a port of djbsort's
    `crypto_sort_int32`. Result: keypair **42.7x**, encapsulate **22.9x**, decapsulate
    **72.6x** faster than PQClean's C reference — at parity with liboqs's hand-tuned AVX2
    implementation on all three operations.
  - aarch64 (Apple M2 Max): NEON divstep inversion, row-major schoolbook multiplies with
    eight independent widening multiply-accumulate chains, NEON small-stride sort passes,
    and a bulk-fill sampler. Result: keypair **2.7x**, encapsulate **1.40x**, decapsulate
    **1.19x** faster than the references' portable C.
- Decapsulation keys cache their decoded public polynomial, and encapsulation keys cache
  the decoded polynomial plus Hash4(pk) — per-key public constants that were previously
  recomputed on every operation.
- The samplers draw randomness with one bulk `fill_bytes` call instead of one RNG call per
  coefficient. Value-identical to the previous per-element stream (pinned by the
  deterministic-keygen KATs), just faster.
- Decapsulation performs no heap allocation; hot-path scratch lives in stack frames sized
  by the largest parameter set.

### Fixed

- The Barrett freeze is now strictly canonical on every path. The bare two-step reduction
  can land a few counts outside ±(q−1)/2 for a small fraction of inputs, which corrupts the
  variable-radix ciphertext/key encoding when it happens; scalar and every SIMD kernel now
  apply the same branchless correction and produce byte-identical results. One NEON kernel
  (`minus_product_shift`) initially missed the correction and was caught by the
  differential suite on first run on ARM hardware.
- Debug-build arithmetic-overflow panics in the row-major multiply kernels' index
  computation (release builds computed correct results; debug builds panicked).

### Security

- Every secret-derived temporary the crate allocates is wiped before it is freed: multiply
  scratch, inversion working state, sampler randomness, encoder working buffers, and the
  SHA-512 helpers' intermediate digests. Wiping goes through the `zeroize` crate or a
  volatile wide-store equivalent; the C reference implementations wipe none of this. One
  documented exception: `generate_key_deterministic`'s ChaCha20 state cannot be wiped
  because `rand_chacha` offers no zeroization support.

## [0.3.0] - 2026-06-12

### Fixed

- sntrup953: the second Barrett constant sat one below its valid window, misreducing
  ~0.7% of reductions and causing rare decapsulation/round-trip failures on every
  platform.

### Changed

- Dependency refresh and CI maintenance.

## [0.2.1] - 2026-05-08

### Fixed

- Windows build fixes.

## [0.2.0] - 2026-05-08

### Changed

- Explicit `unsafe` blocks in the AVX2 kernels for the Rust 2024 edition.

### Fixed

- CI feature-gate and bench-target failures; an armv7 sort bug.

## [0.1.0] - 2026-04-16

Initial release: Streamlined NTRU Prime KEM for all six parameter sets (sntrup653 through
sntrup1277), aligned with the PQClean reference and verified against the IETF draft KAT
vectors.

[0.4.0]: https://github.com/mikelodder7/sntrup/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/mikelodder7/sntrup/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/mikelodder7/sntrup/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mikelodder7/sntrup/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mikelodder7/sntrup/releases/tag/v0.1.0
