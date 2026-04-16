//! Generic Streamlined NTRU Prime types parameterized by parameter set.

use crate::error::Error;
use crate::params::SntrupParams;
use core::marker::PhantomData;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Streamlined NTRU Prime encapsulation key (public key).
#[derive(Clone)]
pub struct EncapsulationKey<P: SntrupParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime decapsulation key (secret key).
#[derive(Clone)]
pub struct DecapsulationKey<P: SntrupParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime ciphertext.
#[derive(Clone)]
pub struct Ciphertext<P: SntrupParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime shared secret.
#[derive(Clone)]
pub struct SharedSecret<P: SntrupParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime Key Encapsulation Mechanism parameterized by parameter set.
///
/// Zero-sized marker type providing [`generate_key`](SntrupKem::generate_key).
/// Use the type aliases [`Sntrup653`](crate::Sntrup653),
/// [`Sntrup761`](crate::Sntrup761), [`Sntrup857`](crate::Sntrup857),
/// [`Sntrup953`](crate::Sntrup953), [`Sntrup1013`](crate::Sntrup1013),
/// [`Sntrup1277`](crate::Sntrup1277).
#[derive(Debug, Clone, Copy)]
pub struct SntrupKem<P: SntrupParams>(PhantomData<P>);

// ---------------------------------------------------------------------------
// Internal constructors
// ---------------------------------------------------------------------------

impl<P: SntrupParams> EncapsulationKey<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<P: SntrupParams> DecapsulationKey<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<P: SntrupParams> Ciphertext<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<P: SntrupParams> SharedSecret<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// DecapsulationKey: extract encapsulation key
// ---------------------------------------------------------------------------

impl<P: SntrupParams> DecapsulationKey<P> {
    /// Get the encapsulation (public) key embedded in this decapsulation key.
    ///
    /// SK layout: f(small_enc) || ginv(small_enc) || pk(pk_size) || rho(small_enc) || hash4(32)
    /// The public key starts at offset `2 * small_encode_size` with length `pk_size`.
    pub fn encapsulation_key(&self) -> EncapsulationKey<P> {
        let params = P::params();
        let pk_start = 2 * params.small_encode_size;
        let pk_end = pk_start + params.pk_size;
        EncapsulationKey::from_vec(self.bytes[pk_start..pk_end].to_vec())
    }
}

// ---------------------------------------------------------------------------
// Debug
// ---------------------------------------------------------------------------

impl<P: SntrupParams> core::fmt::Debug for EncapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::EncapsulationKey", P::NAME);
        f.debug_struct(&name)
            .field("len", &P::PK_BYTES)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: SntrupParams> core::fmt::Debug for DecapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::DecapsulationKey", P::NAME);
        f.debug_struct(&name).finish()
    }
}

impl<P: SntrupParams> core::fmt::Debug for Ciphertext<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::Ciphertext", P::NAME);
        f.debug_struct(&name)
            .field("len", &P::CT_BYTES)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: SntrupParams> core::fmt::Debug for SharedSecret<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::SharedSecret", P::NAME);
        f.debug_struct(&name).finish()
    }
}

// ---------------------------------------------------------------------------
// AsRef<[u8]>
// ---------------------------------------------------------------------------

impl<P: SntrupParams> AsRef<[u8]> for EncapsulationKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: SntrupParams> AsRef<[u8]> for DecapsulationKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: SntrupParams> AsRef<[u8]> for Ciphertext<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: SntrupParams> AsRef<[u8]> for SharedSecret<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// TryFrom<&[u8]>
// ---------------------------------------------------------------------------

impl<P: SntrupParams> TryFrom<&[u8]> for EncapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::PK_BYTES {
            return Err(Error::InvalidSize {
                expected: P::PK_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            _marker: PhantomData,
        })
    }
}

impl<P: SntrupParams> TryFrom<&[u8]> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::SK_BYTES {
            return Err(Error::InvalidSize {
                expected: P::SK_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            _marker: PhantomData,
        })
    }
}

impl<P: SntrupParams> TryFrom<&[u8]> for Ciphertext<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::CT_BYTES {
            return Err(Error::InvalidSize {
                expected: P::CT_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            _marker: PhantomData,
        })
    }
}

impl<P: SntrupParams> TryFrom<Vec<u8>> for EncapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: SntrupParams> TryFrom<&Vec<u8>> for EncapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: SntrupParams> TryFrom<Box<[u8]>> for EncapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

impl<P: SntrupParams> TryFrom<Vec<u8>> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: SntrupParams> TryFrom<&Vec<u8>> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: SntrupParams> TryFrom<Box<[u8]>> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

impl<P: SntrupParams> TryFrom<Vec<u8>> for Ciphertext<P> {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: SntrupParams> TryFrom<&Vec<u8>> for Ciphertext<P> {
    type Error = Error;
    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: SntrupParams> TryFrom<Box<[u8]>> for Ciphertext<P> {
    type Error = Error;
    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

// ---------------------------------------------------------------------------
// PartialEq / Eq (EncapsulationKey, Ciphertext — non-secret, byte equality)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> PartialEq for EncapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: SntrupParams> Eq for EncapsulationKey<P> {}

impl<P: SntrupParams> PartialEq for Ciphertext<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: SntrupParams> Eq for Ciphertext<P> {}

// ---------------------------------------------------------------------------
// ConstantTimeEq / PartialEq / Eq (DecapsulationKey)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> ConstantTimeEq for DecapsulationKey<P> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.as_slice().ct_eq(other.bytes.as_slice())
    }
}

impl<P: SntrupParams> PartialEq for DecapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: SntrupParams> Eq for DecapsulationKey<P> {}

// ---------------------------------------------------------------------------
// ConstantTimeEq / PartialEq / Eq (SharedSecret)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> ConstantTimeEq for SharedSecret<P> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.as_slice().ct_eq(other.bytes.as_slice())
    }
}

impl<P: SntrupParams> PartialEq for SharedSecret<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: SntrupParams> Eq for SharedSecret<P> {}

// ---------------------------------------------------------------------------
// Zeroize + Drop (secret types)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> Zeroize for DecapsulationKey<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: SntrupParams> Drop for DecapsulationKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<P: SntrupParams> Zeroize for SharedSecret<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: SntrupParams> Drop for SharedSecret<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// KEM operations (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "kgen")]
impl<P: SntrupParams> SntrupKem<P> {
    /// Generate a Streamlined NTRU Prime key pair.
    pub fn generate_key(
        rng: &mut impl rand::CryptoRng,
    ) -> (EncapsulationKey<P>, DecapsulationKey<P>) {
        let (pk, sk) = crate::kem::keygen(P::params(), rng);
        (
            EncapsulationKey::from_vec(pk),
            DecapsulationKey::from_vec(sk),
        )
    }

    /// Generate a key pair deterministically from a 32-byte seed.
    ///
    /// The seed is expanded via ChaCha20Rng to derive the full key pair.
    /// Identical seeds always produce identical key pairs.
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey<P>, DecapsulationKey<P>) {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
        Self::generate_key(&mut rng)
    }
}

#[cfg(feature = "ecap")]
impl<P: SntrupParams> EncapsulationKey<P> {
    /// Encapsulate: produce a ciphertext and shared secret.
    pub fn encapsulate(
        &self,
        rng: &mut impl rand::CryptoRng,
    ) -> (Ciphertext<P>, SharedSecret<P>) {
        let (ct, ss) = crate::kem::encaps(&self.bytes, P::params(), rng);
        (Ciphertext::from_vec(ct), SharedSecret::from_vec(ss))
    }
}

#[cfg(feature = "dcap")]
impl<P: SntrupParams> DecapsulationKey<P> {
    /// Decapsulate: recover shared secret from ciphertext.
    ///
    /// Always returns a shared secret (implicit rejection / IND-CCA2).
    /// On failure, returns a pseudorandom key derived from rho,
    /// indistinguishable from a valid key to an attacker.
    pub fn decapsulate(&self, ct: &Ciphertext<P>) -> SharedSecret<P> {
        let ss = crate::kem::decaps(&self.bytes, &ct.bytes, P::params());
        SharedSecret::from_vec(ss)
    }
}

// ---------------------------------------------------------------------------
// Serde (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;

    impl<P: SntrupParams> serde::Serialize for EncapsulationKey<P> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
        }
    }

    impl<'de, P: SntrupParams> serde::Deserialize<'de> for EncapsulationKey<P> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let mut buf = vec![0u8; P::PK_BYTES];
            let _ = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
            Ok(Self {
                bytes: buf,
                _marker: PhantomData,
            })
        }
    }

    impl<P: SntrupParams> serde::Serialize for DecapsulationKey<P> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
        }
    }

    impl<'de, P: SntrupParams> serde::Deserialize<'de> for DecapsulationKey<P> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let mut buf = vec![0u8; P::SK_BYTES];
            let _ = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
            Ok(Self {
                bytes: buf,
                _marker: PhantomData,
            })
        }
    }

    impl<P: SntrupParams> serde::Serialize for Ciphertext<P> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
        }
    }

    impl<'de, P: SntrupParams> serde::Deserialize<'de> for Ciphertext<P> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let mut buf = vec![0u8; P::CT_BYTES];
            let _ = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
            Ok(Self {
                bytes: buf,
                _marker: PhantomData,
            })
        }
    }

    impl<P: SntrupParams> serde::Serialize for SharedSecret<P> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
        }
    }

    impl<'de, P: SntrupParams> serde::Deserialize<'de> for SharedSecret<P> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let mut buf = vec![0u8; P::SS_BYTES];
            let _ = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
            Ok(Self {
                bytes: buf,
                _marker: PhantomData,
            })
        }
    }
}
