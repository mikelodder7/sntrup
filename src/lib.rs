//! Pure Rust implementation of Streamlined NTRU Prime KEM for all parameter sizes.
//!
//! Streamlined NTRU Prime is a lattice-based, quantum-resistant cryptographic
//! algorithm designed for secure key exchange. This crate supports all six
//! parameter sets: sntrup653, sntrup761, sntrup857, sntrup953, sntrup1013,
//! and sntrup1277.
//!
//! # Usage
//!
//! ```rust
//! use sntrup::{Sntrup761, SntrupKem};
//!
//! let mut rng = rand::rng();
//! let (ek, dk) = Sntrup761::generate_key(&mut rng);
//! let (ct, ss1) = ek.encapsulate(&mut rng);
//! let ss2 = dk.decapsulate(&ct);
//! assert_eq!(ss1, ss2);
//! ```
//!
//! # Security Levels
//!
//! - [`Sntrup653`] / [`sntrup653`]: NIST Level 1 (128-bit security) — research/testing only, prefer [`Sntrup761`] or higher for production
//! - [`Sntrup761`] / [`sntrup761`]: NIST Level 2 (128-bit+ security, used by OpenSSH)
//! - [`Sntrup857`] / [`sntrup857`]: NIST Level 3 (192-bit security)
//! - [`Sntrup953`] / [`sntrup953`]: NIST Level 4 (192-bit+ security)
//! - [`Sntrup1013`] / [`sntrup1013`]: NIST Level 5 (256-bit security)
//! - [`Sntrup1277`] / [`sntrup1277`]: NIST Level 5 (256-bit security, with extra margin)
//!
//! # Sizes (bytes)
//!
//! | Parameter Set | NIST Level | Public Key | Secret Key | Ciphertext | Shared Secret |
//! |---------------|------------|------------|------------|------------|---------------|
//! | sntrup653     | 1          | 994        | 1518       | 897        | 32            |
//! | sntrup761     | 2          | 1158       | 1763       | 1039       | 32            |
//! | sntrup857     | 3          | 1322       | 1999       | 1184       | 32            |
//! | sntrup953     | 4          | 1505       | 2254       | 1349       | 32            |
//! | sntrup1013    | 5          | 1623       | 2417       | 1455       | 32            |
//! | sntrup1277    | 5          | 2067       | 3059       | 1847       | 32            |
//!
//! # Features
//!
//! - `kgen`: Key generation (default)
//! - `ecap`: Encapsulation (default)
//! - `dcap`: Decapsulation (default)
//! - `serde`: Serde serialization support via `serdect`

mod error;
mod kem;
mod params;
mod r3;
mod rq;
mod types;
mod utils;
mod zx;

pub use error::Error;
pub use params::{
    Sntrup1013Params, Sntrup1277Params, Sntrup653Params, Sntrup761Params, Sntrup857Params,
    Sntrup953Params, SntrupParams,
};
pub use types::{Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret, SntrupKem};

/// sntrup653 KEM (NIST Level 1, 128-bit security).
///
/// **Not recommended for production use.** The 653 parameter set provides the
/// lowest security margin. Prefer [`Sntrup761`] or higher for production deployments.
pub type Sntrup653 = SntrupKem<Sntrup653Params>;
/// sntrup761 KEM (NIST Level 2, 128-bit+ security, used by OpenSSH).
pub type Sntrup761 = SntrupKem<Sntrup761Params>;
/// sntrup857 KEM (NIST Level 3, 192-bit security).
pub type Sntrup857 = SntrupKem<Sntrup857Params>;
/// sntrup953 KEM (NIST Level 4, 192-bit+ security).
pub type Sntrup953 = SntrupKem<Sntrup953Params>;
/// sntrup1013 KEM (NIST Level 5, 256-bit security).
pub type Sntrup1013 = SntrupKem<Sntrup1013Params>;
/// sntrup1277 KEM (NIST Level 5, 256-bit security).
pub type Sntrup1277 = SntrupKem<Sntrup1277Params>;

/// sntrup653: NIST Level 1 (128-bit security), p=653, q=4621, w=288.
///
/// **Not recommended for production use.** Prefer [`sntrup761`] or higher.
pub mod sntrup653 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 994;
    /// Secret key size in bytes.
    pub const SECRET_KEY_SIZE: usize = 1518;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 897;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;

    /// sntrup653 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Sntrup653Params>;
    /// sntrup653 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Sntrup653Params>;
    /// sntrup653 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Sntrup653Params>;
    /// sntrup653 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Sntrup653Params>;

    /// Generate an sntrup653 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(
        rng: &mut impl rand::CryptoRng,
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup653::generate_key(rng)
    }

    /// Generate an sntrup653 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup653::generate_key_deterministic(seed)
    }
}

/// sntrup761: NIST Level 2 (128-bit+ security), p=761, q=4591, w=286. Used by OpenSSH.
pub mod sntrup761 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 1158;
    /// Secret key size in bytes.
    pub const SECRET_KEY_SIZE: usize = 1763;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 1039;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;

    /// sntrup761 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Sntrup761Params>;
    /// sntrup761 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Sntrup761Params>;
    /// sntrup761 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Sntrup761Params>;
    /// sntrup761 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Sntrup761Params>;

    /// Generate an sntrup761 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(
        rng: &mut impl rand::CryptoRng,
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup761::generate_key(rng)
    }

    /// Generate an sntrup761 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup761::generate_key_deterministic(seed)
    }
}

/// sntrup857: NIST Level 3 (192-bit security), p=857, q=5167, w=322.
pub mod sntrup857 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 1322;
    /// Secret key size in bytes.
    pub const SECRET_KEY_SIZE: usize = 1999;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 1184;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;

    /// sntrup857 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Sntrup857Params>;
    /// sntrup857 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Sntrup857Params>;
    /// sntrup857 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Sntrup857Params>;
    /// sntrup857 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Sntrup857Params>;

    /// Generate an sntrup857 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(
        rng: &mut impl rand::CryptoRng,
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup857::generate_key(rng)
    }

    /// Generate an sntrup857 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup857::generate_key_deterministic(seed)
    }
}

/// sntrup953: NIST Level 4 (192-bit+ security), p=953, q=6343, w=396.
pub mod sntrup953 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 1505;
    /// Secret key size in bytes.
    pub const SECRET_KEY_SIZE: usize = 2254;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 1349;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;

    /// sntrup953 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Sntrup953Params>;
    /// sntrup953 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Sntrup953Params>;
    /// sntrup953 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Sntrup953Params>;
    /// sntrup953 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Sntrup953Params>;

    /// Generate an sntrup953 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(
        rng: &mut impl rand::CryptoRng,
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup953::generate_key(rng)
    }

    /// Generate an sntrup953 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup953::generate_key_deterministic(seed)
    }
}

/// sntrup1013: NIST Level 5 (256-bit security), p=1013, q=7177, w=448.
pub mod sntrup1013 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 1623;
    /// Secret key size in bytes.
    pub const SECRET_KEY_SIZE: usize = 2417;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 1455;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;

    /// sntrup1013 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Sntrup1013Params>;
    /// sntrup1013 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Sntrup1013Params>;
    /// sntrup1013 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Sntrup1013Params>;
    /// sntrup1013 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Sntrup1013Params>;

    /// Generate an sntrup1013 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(
        rng: &mut impl rand::CryptoRng,
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup1013::generate_key(rng)
    }

    /// Generate an sntrup1013 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup1013::generate_key_deterministic(seed)
    }
}

/// sntrup1277: NIST Level 5 (256-bit security, extra margin), p=1277, q=7879, w=492.
pub mod sntrup1277 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 2067;
    /// Secret key size in bytes.
    pub const SECRET_KEY_SIZE: usize = 3059;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 1847;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;

    /// sntrup1277 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Sntrup1277Params>;
    /// sntrup1277 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Sntrup1277Params>;
    /// sntrup1277 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Sntrup1277Params>;
    /// sntrup1277 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Sntrup1277Params>;

    /// Generate an sntrup1277 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(
        rng: &mut impl rand::CryptoRng,
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup1277::generate_key(rng)
    }

    /// Generate an sntrup1277 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Sntrup1277::generate_key_deterministic(seed)
    }
}
