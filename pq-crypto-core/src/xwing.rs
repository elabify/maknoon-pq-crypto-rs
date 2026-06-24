// X-Wing HPKE (RFC 9180 Base mode) for the Verify & Pay seal.
//
// Byte-exact interop with Apple CryptoKit's
// `HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256` is proven, both
// directions, by `tests/xwing_parity.rs` (the live CryptoKit oracle) plus a
// deterministic offline KAT. The commerce-critical direction is Rust seals
// -> CryptoKit opens (the Android holder seals its presentation + payment
// proof to the iOS merchant's published public key).
//
//   KEM  = X-Wing (ML-KEM-768 + X25519)   kem_id  = 0x647A
//   KDF  = HKDF-SHA256                     kdf_id  = 0x0001
//   AEAD = AES-256-GCM                     aead_id = 0x0002
//
// X-Wing is a standalone KEM (not DHKEM): its 32-byte SHA3-256 combiner
// output is fed DIRECTLY into the HPKE key schedule as `shared_secret`, with
// no KEM-level ExtractAndExpand and no enc/pkR in the key schedule. We
// implement only single-shot Base mode (seq=0), no AAD, no PSK -- exactly
// what iOS CommerceSeal does. The `info` bytes are built by the caller as
// UTF-8 "elabify-engage-1|<sessionId>|<serviceUuid>" (serviceUuid = "commerce"
// for Verify & Pay), matching iOS TransportCiphersuite.info.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x_wing::{
    Ciphertext, Decapsulate, DecapsulationKey, Decapsulator, EncapsulationKey, KeyExport,
};

use crate::PqError;

const KEM_ID: u16 = 0x647A;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0002;
const NK: usize = 32; // AES-256 key
const NN: usize = 12; // GCM nonce
const NH: usize = 32; // SHA-256 output

/// X-Wing public key (encapsulation key) byte length: pk_m(1184) || pk_x(32).
pub const XWING_PUBLIC_KEY_LEN: usize = 1216;
/// X-Wing secret (decapsulation) key byte length.
pub const XWING_SECRET_KEY_LEN: usize = 32;
/// X-Wing encapsulated key (ciphertext) length: ct_m(1088) || ct_x(32).
pub const XWING_ENCAPSULATED_KEY_LEN: usize = 1120;
/// Randomness consumed by deterministic encapsulation (32 ML-KEM || 32 X25519).
pub const XWING_ENCAPS_RANDOMNESS_LEN: usize = 64;

fn suite_id() -> Vec<u8> {
    let mut v = b"HPKE".to_vec();
    v.extend_from_slice(&KEM_ID.to_be_bytes());
    v.extend_from_slice(&KDF_ID.to_be_bytes());
    v.extend_from_slice(&AEAD_ID.to_be_bytes());
    v
}

/// RFC 9180 LabeledExtract: Extract(salt, "HPKE-v1" || suite_id || label || ikm).
fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut msg = b"HPKE-v1".to_vec();
    msg.extend_from_slice(&suite_id());
    msg.extend_from_slice(label);
    msg.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// RFC 9180 LabeledExpand:
/// Expand(prk, I2OSP(len,2) || "HPKE-v1" || suite_id || label || info, len).
fn labeled_expand(prk: &[u8; 32], label: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut labeled_info = (len as u16).to_be_bytes().to_vec();
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(&suite_id());
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("prk len ok");
    let mut okm = vec![0u8; len];
    hk.expand(&labeled_info, &mut okm).expect("expand ok");
    okm
}

/// RFC 9180 Base-mode key schedule -> (key, base_nonce).
fn key_schedule(shared_secret: &[u8], info: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let psk_id_hash = labeled_extract(b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(b"", b"info_hash", info);
    // key_schedule_context = mode(0x00 Base) || psk_id_hash || info_hash
    let mut ksc = vec![0x00u8];
    ksc.extend_from_slice(&psk_id_hash);
    ksc.extend_from_slice(&info_hash);
    let secret = labeled_extract(shared_secret, b"secret", b"");
    let key = labeled_expand(&secret, b"key", &ksc, NK);
    let base_nonce = labeled_expand(&secret, b"base_nonce", &ksc, NN);
    let _exporter = labeled_expand(&secret, b"exp", &ksc, NH);
    (key, base_nonce)
}

fn aead_seal(key: &[u8], base_nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>, PqError> {
    // seq = 0 -> nonce = base_nonce, no AAD (single-shot).
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PqError::XWingSealFailed)?;
    let nonce = Nonce::from_slice(base_nonce);
    cipher
        .encrypt(nonce, pt)
        .map_err(|_| PqError::XWingSealFailed)
}

fn aead_open(key: &[u8], base_nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, PqError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PqError::XWingOpenFailed)?;
    let nonce = Nonce::from_slice(base_nonce);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| PqError::XWingOpenFailed)
}

fn secret_array(sk: &[u8]) -> Result<[u8; 32], PqError> {
    sk.try_into().map_err(|_| PqError::BadXWingKeyLength)
}

fn parse_pub(pk: &[u8]) -> Result<EncapsulationKey, PqError> {
    if pk.len() != XWING_PUBLIC_KEY_LEN {
        return Err(PqError::BadXWingKeyLength);
    }
    EncapsulationKey::try_from(pk).map_err(|_| PqError::BadXWingKeyLength)
}

// ---- pure typed API (used by the uniffi surface + the Rust KAT tests) ----

/// Derive the X-Wing public key (1216 B, pk_m || pk_x) from a 32-byte secret.
/// Matches CryptoKit `XWingMLKEM768X25519.PublicKey.rawRepresentation`.
pub fn xwing_public_key_from_secret(secret_key: &[u8; 32]) -> Vec<u8> {
    let dk = DecapsulationKey::from(*secret_key);
    dk.encapsulation_key().to_bytes()[..].to_vec()
}

/// Deterministic seal: encapsulate to `recipient_public_key` using the given
/// 64 bytes of randomness, run the HPKE Base-mode key schedule over `info`,
/// and AES-256-GCM seal `plaintext`. Returns (encapsulated_key, ciphertext).
/// Deterministic so it can be pinned as an offline KAT.
pub fn xwing_seal_deterministic(
    recipient_public_key: &[u8],
    info: &[u8],
    plaintext: &[u8],
    encaps_randomness: &[u8; 64],
) -> Result<(Vec<u8>, Vec<u8>), PqError> {
    let ek = parse_pub(recipient_public_key)?;
    let (ct, ss) = ek.encapsulate_deterministic(&(*encaps_randomness).into());
    let (key, base_nonce) = key_schedule(&ss[..], info);
    let sealed = aead_seal(&key, &base_nonce, plaintext)?;
    Ok((ct[..].to_vec(), sealed))
}

/// Open a sealed envelope with the recipient's 32-byte secret key.
pub fn xwing_open_with_secret(
    secret_key: &[u8; 32],
    encapsulated_key: &[u8],
    info: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PqError> {
    if encapsulated_key.len() != XWING_ENCAPSULATED_KEY_LEN {
        return Err(PqError::BadEncapsulatedKeyLength);
    }
    let dk = DecapsulationKey::from(*secret_key);
    let mut ct_arr = [0u8; XWING_ENCAPSULATED_KEY_LEN];
    ct_arr.copy_from_slice(encapsulated_key);
    let ct: Ciphertext = ct_arr.into();
    let ss = dk.decapsulate(&ct);
    let (key, base_nonce) = key_schedule(&ss[..], info);
    aead_open(&key, &base_nonce, ciphertext)
}

fn fresh_bytes<const N: usize>() -> Result<[u8; N], PqError> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| PqError::XWingSealFailed)?;
    Ok(b)
}

// ---- UniFFI surface (Kotlin/Swift). Owned bytes in/out. ----

/// Result of a single-shot X-Wing HPKE seal.
#[derive(uniffi::Record)]
pub struct XWingSealed {
    /// HPKE encapsulated key (1120 B) to publish alongside the ciphertext.
    pub encapsulated_key: Vec<u8>,
    /// AES-256-GCM ciphertext (plaintext + 16-byte tag).
    pub ciphertext: Vec<u8>,
}

/// Generate a fresh 32-byte X-Wing secret (decapsulation) key.
#[uniffi::export]
pub fn xwing_generate_secret_key() -> Result<Vec<u8>, PqError> {
    Ok(fresh_bytes::<XWING_SECRET_KEY_LEN>()?.to_vec())
}

/// Public key (1216 B) for a 32-byte secret key.
#[uniffi::export]
pub fn xwing_public_key(secret_key: Vec<u8>) -> Result<Vec<u8>, PqError> {
    Ok(xwing_public_key_from_secret(&secret_array(&secret_key)?))
}

/// Seal `plaintext` to `recipient_public_key` under `info`, using fresh OS
/// randomness for the encapsulation. Single-shot HPKE Base mode (seq=0).
#[uniffi::export]
pub fn xwing_seal(
    recipient_public_key: Vec<u8>,
    info: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<XWingSealed, PqError> {
    let randomness = fresh_bytes::<XWING_ENCAPS_RANDOMNESS_LEN>()?;
    let (enc, ct) =
        xwing_seal_deterministic(&recipient_public_key, &info, &plaintext, &randomness)?;
    Ok(XWingSealed {
        encapsulated_key: enc,
        ciphertext: ct,
    })
}

/// Open a sealed envelope produced by `xwing_seal` (or CryptoKit), using the
/// recipient's 32-byte secret key.
#[uniffi::export]
pub fn xwing_open(
    secret_key: Vec<u8>,
    encapsulated_key: Vec<u8>,
    info: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, PqError> {
    xwing_open_with_secret(
        &secret_array(&secret_key)?,
        &encapsulated_key,
        &info,
        &ciphertext,
    )
}
