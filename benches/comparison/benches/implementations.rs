//! Cross-implementation sntrup761 benchmarks.
//!
//! sntrup761 is the only parameter set this crate supports that either comparison crate also
//! implements — `pqcrypto-ntruprime` (PQClean's C reference/optimized implementations) and
//! `oqs` (liboqs, which vendors the same PQClean sources) both stop at sntrup761. See the
//! adjacent README for run instructions.

use std::{hint::black_box, time::Duration};

use criterion::{BenchmarkId, Criterion};
use pqcrypto_ntruprime::sntrup761 as pqclean;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret};
use sntrup::Sntrup761;

const PARAMETER_SET: &str = "sntrup761";

fn check_parameters(liboqs: &oqs::kem::Kem) {
    let (pk, sk) = sntrup::sntrup761::generate_key(&mut rand::rng());
    assert_eq!(pk.as_ref().len(), sntrup::sntrup761::PUBLIC_KEY_SIZE);
    assert_eq!(sk.as_ref().len(), sntrup::sntrup761::SECRET_KEY_SIZE);

    let (pqclean_pk, pqclean_sk) = pqclean::keypair();
    assert_eq!(
        pqclean_pk.as_bytes().len(),
        sntrup::sntrup761::PUBLIC_KEY_SIZE
    );
    assert_eq!(
        pqclean_sk.as_bytes().len(),
        sntrup::sntrup761::SECRET_KEY_SIZE
    );

    assert_eq!(
        liboqs.length_public_key(),
        sntrup::sntrup761::PUBLIC_KEY_SIZE
    );
    assert_eq!(
        liboqs.length_secret_key(),
        sntrup::sntrup761::SECRET_KEY_SIZE
    );
    assert_eq!(
        liboqs.length_ciphertext(),
        sntrup::sntrup761::CIPHERTEXT_SIZE
    );
    assert_eq!(
        liboqs.length_shared_secret(),
        sntrup::sntrup761::SHARED_SECRET_SIZE
    );
}

fn keypair(c: &mut Criterion, liboqs: &oqs::kem::Kem) {
    let mut group = c.benchmark_group("keypair");
    group.sample_size(10);

    let mut our_rng = rand::rng();
    group.bench_function(BenchmarkId::new(PARAMETER_SET, "sntrup"), |b| {
        b.iter(|| black_box(Sntrup761::generate_key(&mut our_rng)));
    });

    group.bench_function(BenchmarkId::new(PARAMETER_SET, "PQClean"), |b| {
        b.iter(|| black_box(pqclean::keypair()));
    });

    group.bench_function(BenchmarkId::new(PARAMETER_SET, "liboqs"), |b| {
        b.iter(|| black_box(liboqs.keypair().expect("liboqs keypair")));
    });

    group.finish();
}

fn encapsulate(c: &mut Criterion, liboqs: &oqs::kem::Kem) {
    let mut our_rng = rand::rng();
    let (our_pk, _) = Sntrup761::generate_key(&mut our_rng);

    let (pqclean_pk, _) = pqclean::keypair();

    let (liboqs_pk, _) = liboqs.keypair().expect("liboqs keypair");

    let mut group = c.benchmark_group("encapsulate");
    group.bench_function(BenchmarkId::new(PARAMETER_SET, "sntrup"), |b| {
        b.iter(|| black_box(our_pk.encapsulate(&mut our_rng)));
    });

    group.bench_function(BenchmarkId::new(PARAMETER_SET, "PQClean"), |b| {
        b.iter(|| black_box(pqclean::encapsulate(&pqclean_pk)));
    });

    group.bench_function(BenchmarkId::new(PARAMETER_SET, "liboqs"), |b| {
        b.iter(|| black_box(liboqs.encapsulate(&liboqs_pk).expect("liboqs encapsulate")));
    });

    group.finish();
}

fn decapsulate(c: &mut Criterion, liboqs: &oqs::kem::Kem) {
    let mut our_rng = rand::rng();
    let (our_pk, our_sk) = Sntrup761::generate_key(&mut our_rng);
    let (our_ct, our_sent) = our_pk.encapsulate(&mut our_rng);
    assert_eq!(our_sk.decapsulate(&our_ct), our_sent);

    let (pqclean_pk, pqclean_sk) = pqclean::keypair();
    let (pqclean_sent, pqclean_ct) = pqclean::encapsulate(&pqclean_pk);
    assert_eq!(
        pqclean::decapsulate(&pqclean_ct, &pqclean_sk).as_bytes(),
        pqclean_sent.as_bytes()
    );

    let (liboqs_pk, liboqs_sk) = liboqs.keypair().expect("liboqs keypair");
    let (liboqs_ct, liboqs_sent) = liboqs.encapsulate(&liboqs_pk).expect("liboqs encapsulate");
    let liboqs_received = liboqs
        .decapsulate(&liboqs_sk, &liboqs_ct)
        .expect("liboqs decapsulate");
    assert_eq!(liboqs_received.as_ref(), liboqs_sent.as_ref());

    let mut group = c.benchmark_group("decapsulate");
    group.bench_function(BenchmarkId::new(PARAMETER_SET, "sntrup"), |b| {
        b.iter(|| black_box(our_sk.decapsulate(&our_ct)));
    });

    group.bench_function(BenchmarkId::new(PARAMETER_SET, "PQClean"), |b| {
        b.iter(|| black_box(pqclean::decapsulate(&pqclean_ct, &pqclean_sk)));
    });

    group.bench_function(BenchmarkId::new(PARAMETER_SET, "liboqs"), |b| {
        b.iter(|| {
            black_box(
                liboqs
                    .decapsulate(&liboqs_sk, &liboqs_ct)
                    .expect("liboqs decapsulate"),
            )
        });
    });

    group.finish();
}

fn run() {
    oqs::init();
    let liboqs = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeSntrup761)
        .expect("liboqs built with sntrup761 support");

    check_parameters(&liboqs);

    let mut criterion = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .configure_from_args();
    keypair(&mut criterion, &liboqs);
    encapsulate(&mut criterion, &liboqs);
    decapsulate(&mut criterion, &liboqs);
    criterion.final_summary();
}

fn main() {
    run();
}
