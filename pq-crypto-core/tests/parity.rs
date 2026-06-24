// Cross-platform PQ parity: the Rust ML-DSA-65 must reproduce the public
// keys Apple CryptoKit derives from the same 32-byte seed, and must
// cross-verify CryptoKit's signatures. Vectors are generated on macOS 26
// by code/pq-crypto-rs/tools/cryptokit_oracle.swift into
// elabify-core/test-vectors/mldsa65.kat.json.

use std::path::PathBuf;

use serde::Deserialize;

use pq_crypto_core::{mldsa65_public_key_from_seed, mldsa65_sign_deterministic, mldsa65_verify};

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "seedHex")]
    seed_hex: String,
    #[serde(rename = "publicKeyHex")]
    public_key_hex: String,
    #[serde(rename = "messageHex")]
    message_hex: String,
    #[serde(rename = "signatureHex")]
    signature_hex: String,
}

#[derive(Deserialize)]
struct Corpus {
    vectors: Vec<Vector>,
}

fn corpus_path() -> PathBuf {
    // tests/ -> pq-crypto-core/ -> pq-crypto-rs/test-vectors/
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/mldsa65.kat.json")
}

fn seed32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("seed hex");
    let mut s = [0u8; 32];
    s.copy_from_slice(&bytes);
    s
}

#[test]
fn mldsa65_seed_to_pubkey_matches_cryptokit() {
    let raw = std::fs::read_to_string(corpus_path()).expect("read mldsa65.kat.json");
    let corpus: Corpus = serde_json::from_str(&raw).expect("parse corpus");
    assert!(!corpus.vectors.is_empty(), "corpus must not be empty");

    for v in &corpus.vectors {
        let seed = seed32(&v.seed_hex);
        let pk = mldsa65_public_key_from_seed(&seed);
        assert_eq!(
            hex::encode(&pk),
            v.public_key_hex,
            "ML-DSA-65 pubkey mismatch vs CryptoKit for seed {}",
            &v.seed_hex
        );
        assert_eq!(pk.len(), 1952);
    }
}

#[test]
fn cross_verify_cryptokit_signatures() {
    let raw = std::fs::read_to_string(corpus_path()).expect("read mldsa65.kat.json");
    let corpus: Corpus = serde_json::from_str(&raw).expect("parse corpus");

    for v in &corpus.vectors {
        let pk = hex::decode(&v.public_key_hex).unwrap();
        let msg = hex::decode(&v.message_hex).unwrap();
        let sig = hex::decode(&v.signature_hex).unwrap();
        // A CryptoKit signature must verify under the Rust verifier.
        assert!(
            mldsa65_verify(&pk, &sig, &msg),
            "Rust failed to verify a CryptoKit ML-DSA-65 signature (seed {})",
            &v.seed_hex
        );
    }
}

#[test]
fn rust_sign_verifies_under_cryptokit_pubkey() {
    let raw = std::fs::read_to_string(corpus_path()).expect("read mldsa65.kat.json");
    let corpus: Corpus = serde_json::from_str(&raw).expect("parse corpus");

    for v in &corpus.vectors {
        let seed = seed32(&v.seed_hex);
        let msg = hex::decode(&v.message_hex).unwrap();
        let sig = mldsa65_sign_deterministic(&seed, &msg);
        assert_eq!(sig.len(), 3309);
        let pk = hex::decode(&v.public_key_hex).unwrap();
        // Round-trip: a Rust signature verifies under the CryptoKit-derived pubkey.
        assert!(
            mldsa65_verify(&pk, &sig, &msg),
            "Rust signature did not verify under CryptoKit pubkey (seed {})",
            &v.seed_hex
        );
    }
}
