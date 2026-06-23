// Maknoon post-quantum core: ML-DSA-65 + ML-KEM-768 + BIP39.
//
// The Android port must reproduce, byte-for-byte, the keys Apple CryptoKit
// derives on iOS. The master identity key is ML-DSA-65 derived
// deterministically from a 32-byte seed (the FIPS-204 keygen seed xi).
// Parity with CryptoKit + @noble/post-quantum is enforced by the KAT
// corpus at elabify-core/test-vectors (see tests/parity.rs).

use ml_dsa::signature::Verifier;
use ml_dsa::{B32, EncodedSignature, MlDsa65, Signature, SigningKey, VerifyingKey};

uniffi::setup_scaffolding!();

/// X-Wing HPKE transport for the Verify & Pay seal (ADR-0031). Exposes its own
/// `#[uniffi::export]` functions; the scaffolding above is crate-wide.
pub mod xwing;

/// ML-DSA-65 byte lengths (FIPS-204).
const MLDSA65_PK_LEN: usize = 1952;
const MLDSA65_SIG_LEN: usize = 3309;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PqError {
    #[error("seed must be 32 bytes")]
    BadSeedLength,
    #[error("public key must be 1952 bytes")]
    BadPublicKeyLength,
    #[error("signature must be 3309 bytes")]
    BadSignatureLength,
    #[error("signing failed")]
    SignFailed,
    #[error("X-Wing key must be 32 bytes (secret) or 1216 bytes (public)")]
    BadXWingKeyLength,
    #[error("X-Wing encapsulated key must be 1120 bytes")]
    BadEncapsulatedKeyLength,
    #[error("X-Wing HPKE seal failed")]
    XWingSealFailed,
    #[error("X-Wing HPKE open failed")]
    XWingOpenFailed,
}

fn seed_array(seed: &[u8]) -> Result<[u8; 32], PqError> {
    seed.try_into().map_err(|_| PqError::BadSeedLength)
}

// ---- UniFFI surface (Kotlin/Swift). Takes/returns owned bytes; the
// pure typed fns below back these and are used by the Rust KAT tests. ----

/// ML-DSA-65 public key (1952 B) from a 32-byte seed.
#[uniffi::export]
pub fn mldsa65_public_key(seed: Vec<u8>) -> Result<Vec<u8>, PqError> {
    Ok(mldsa65_public_key_from_seed(&seed_array(&seed)?))
}

/// Deterministic ML-DSA-65 signature (3309 B), empty context.
#[uniffi::export]
pub fn mldsa65_sign(seed: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, PqError> {
    Ok(mldsa65_sign_deterministic(&seed_array(&seed)?, &message))
}

/// Verify an ML-DSA-65 signature against a raw public key + message.
#[uniffi::export]
pub fn mldsa65_verify_signature(public_key: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    if public_key.len() != MLDSA65_PK_LEN || signature.len() != MLDSA65_SIG_LEN {
        return false;
    }
    mldsa65_verify(&public_key, &signature, &message)
}

/// Derive the ML-DSA-65 public key (raw FIPS-204 encoding, 1952 bytes)
/// from a 32-byte seed. Matches CryptoKit
/// `MLDSA65.PrivateKey(seedRepresentation:).publicKey.rawRepresentation`.
pub fn mldsa65_public_key_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let xi: B32 = (*seed).into();
    let sk = SigningKey::<MlDsa65>::from_seed(&xi);
    sk.expanded_key().verifying_key().encode().as_slice().to_vec()
}

/// Sign `message` deterministically (empty context) with the master key
/// derived from `seed`. Deterministic so the signature is itself a KAT;
/// CryptoKit's signer is hedged, so we cross-verify rather than compare
/// bytes against CryptoKit.
pub fn mldsa65_sign_deterministic(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let xi: B32 = (*seed).into();
    let sk = SigningKey::<MlDsa65>::from_seed(&xi);
    let sig = sk
        .expanded_key()
        .sign_deterministic(message, &[])
        .expect("ML-DSA-65 deterministic sign");
    sig.encode().as_slice().to_vec()
}

/// Verify an ML-DSA-65 signature (raw 3309-byte encoding) against a raw
/// 1952-byte public key and message (empty context).
pub fn mldsa65_verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    let pk_arr: &ml_dsa::EncodedVerifyingKey<MlDsa65> = match public_key.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa65>::decode(pk_arr);
    let sig_arr: &EncodedSignature<MlDsa65> = match signature.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig = match Signature::<MlDsa65>::decode(sig_arr) {
        Some(s) => s,
        None => return false,
    };
    vk.verify(message, &sig).is_ok()
}
