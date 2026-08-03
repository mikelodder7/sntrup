# Cross-implementation benchmarks

This standalone Criterion harness compares the public KEM APIs of three crates from crates.io,
all implementing sntrup761 — the one parameter set every comparator here supports (this crate's
other five sizes have no independent implementation to compare against):

- `sntrup` (the current checkout): pure Rust, with hand-written AVX2/NEON kernels for the
  dominant O(p²) polynomial multiply.
- `pqcrypto-ntruprime` 0.1.6, labelled `PQClean`: Rust wrappers around PQClean's C reference
  implementation for sntrup761. Built here without its `avx2` feature, so it always runs the
  portable "clean" C code, on every architecture.
- `oqs` 0.11.0, labelled `liboqs`: Rust bindings to liboqs (vendors the same PQClean sources).

Run it:

```sh
cargo bench --manifest-path benches/comparison/Cargo.toml
```

The harness measures key-pair generation, encapsulation, and decapsulation. Setup and
round-trip validation happen outside timed regions; `check_parameters` asserts all three
report identical public-key / secret-key / ciphertext / shared-secret sizes before any
benchmark runs, so a silent parameter mismatch fails loudly instead of skewing numbers.

Randomness is implementation-specific: our own `keypair`/`encapsulate` benches use `rand::rng()`
(process-local, OS-seeded); PQClean and liboqs draw from the OS RNG internally through their C
APIs, which take no caller-supplied generator — this matches the NIST reference API convention
both were built against.

Criterion uses a 1 second warm-up and 3 second measurement window. Key generation uses the
minimum supported sample size of 10 because it is comparatively expensive. Results are written
beneath `benches/comparison/target/criterion/`.

See [RESULTS.md](RESULTS.md) for one complete run and its machine/build details.
