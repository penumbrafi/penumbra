//! Hex encoding of curve values for the JSON wire format.
//!
//! Everything goes through osst's own canonical encodings —
//! [`OsstPoint::compress`]/[`OsstPoint::decompress`] and
//! [`OsstScalar::to_bytes`]/[`OsstScalar::from_canonical_bytes`] — rather than
//! the curve crate's `GroupEncoding`/`PrimeField` reprs. Those are the bytes
//! osst hashes into binding factors, challenges, proofs of knowledge and the
//! Noise prologue; a wire format that encoded points any other way would be
//! one refactor away from disagreeing with them silently.
//!
//! `decompress` rejects non-canonical encodings rather than coercing them, so
//! a peer cannot smuggle in a second spelling of a point it also sent
//! honestly.

use osst::curve::{OsstPoint, OsstScalar};
use pasta_curves::pallas::{Point as PallasPoint, Scalar as PallasScalar};

/// Canonical compressed point as hex.
pub fn point_hex(p: &PallasPoint) -> String {
    hex::encode(p.compress())
}

/// Parse a canonical compressed point from hex.
pub fn point_from_hex(s: &str) -> Option<PallasPoint> {
    let bytes = hex::decode(s).ok()?;
    PallasPoint::decompress(&bytes)
}

/// Canonical scalar as hex.
pub fn scalar_hex(s: &PallasScalar) -> String {
    hex::encode(s.to_bytes())
}

/// Parse a canonical scalar from hex.
pub fn scalar_from_hex(s: &str) -> Option<PallasScalar> {
    let bytes = hex::decode(s).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    PallasScalar::from_canonical_bytes(&arr)
}

/// Parse a canonical scalar of the curve `P` works over, from hex.
///
/// Generic so that [`crate::agreement`] can verify evidence without naming
/// Pallas — the module is meant to move upstream.
pub fn scalar_from_hex_of<P: OsstPoint>(s: &str) -> Option<P::Scalar> {
    let bytes = hex::decode(s).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    P::Scalar::from_canonical_bytes(&arr)
}

/// Serde for a `[u8; 32]` as a hex string, so a session id or a digest reads
/// the same on the wire as everything else here.
pub mod bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn points_and_scalars_round_trip() {
        let s = PallasScalar::from_u32(12345);
        assert_eq!(scalar_from_hex(&scalar_hex(&s)), Some(s));

        let p = PallasPoint::generator().mul_scalar(&s);
        assert_eq!(point_from_hex(&point_hex(&p)), Some(p));
    }

    #[test]
    fn short_and_malformed_encodings_are_rejected() {
        assert!(point_from_hex("00").is_none());
        assert!(point_from_hex("zz").is_none());
        assert!(scalar_from_hex(&hex::encode([0xffu8; 32])).is_none());
    }
}
