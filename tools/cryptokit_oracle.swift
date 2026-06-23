// CryptoKit ground-truth oracle for the cross-platform PQ KAT corpus.
//
// Maknoon's iOS master identity key is CryptoKit's ML-DSA-65 derived
// deterministically from a 32-byte seed (MLDSAClient.swift:
// `MLDSA65.PrivateKey(seedRepresentation:)` -> `publicKey.rawRepresentation`).
// The Android port must reproduce that public key byte-for-byte from the
// same seed. CryptoKit ships these symbols on macOS 26 / iOS 26.
//
// This emits a JSON vector set (seed -> pubkey, plus a self-verifying
// signature) that `pq-crypto-rs` is tested against. Run on macOS 26:
//
//   swift code/pq-crypto-rs/tools/cryptokit_oracle.swift > \
//     code/pq-crypto-rs/test-vectors/mldsa65.kat.json
//
// ML-DSA signing in CryptoKit is hedged (non-deterministic), so the
// signature is NOT a fixed KAT; the contract we pin is (a) seed->pubkey
// determinism and (b) cross-verification: a CryptoKit signature verifies
// under the Rust public key and vice versa. The signature here is emitted
// only so the Rust side can assert it verifies.

import Foundation
import CryptoKit

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

// Deterministic, human-auditable seeds: all-zero, all-0x07 (matches the
// backend reissue test fixture), a counting pattern, and 0xff.
let seeds: [[UInt8]] = [
    Array(repeating: 0x00, count: 32),
    Array(repeating: 0x07, count: 32),
    (0..<32).map { UInt8($0) },
    Array(repeating: 0xff, count: 32),
]

let message = Array("elabify-pq-kat:v1".utf8)

struct Vector: Codable {
    let seedHex: String
    let publicKeyHex: String
    let publicKeyLen: Int
    let messageHex: String
    let signatureHex: String
    let signatureLen: Int
}

var vectors: [Vector] = []
for seed in seeds {
    let sk = try MLDSA65.PrivateKey(seedRepresentation: Data(seed), publicKey: nil)
    let pk = sk.publicKey.rawRepresentation
    let sig = try sk.signature(for: Data(message))
    // Sanity: CryptoKit verifies its own signature.
    precondition(sk.publicKey.isValidSignature(sig, for: Data(message)))
    vectors.append(Vector(
        seedHex: hex(Data(seed)),
        publicKeyHex: hex(pk),
        publicKeyLen: pk.count,
        messageHex: hex(Data(message)),
        signatureHex: hex(sig),
        signatureLen: sig.count
    ))
}

let out: [String: Any] = [
    "algorithm": "ML-DSA-65",
    "source": "Apple CryptoKit (macOS 26)",
    "note": "seed->publicKey is deterministic; signature is hedged, pin cross-verify not bytes",
    "vectors": vectors.map { [
        "seedHex": $0.seedHex,
        "publicKeyHex": $0.publicKeyHex,
        "publicKeyLen": $0.publicKeyLen,
        "messageHex": $0.messageHex,
        "signatureHex": $0.signatureHex,
        "signatureLen": $0.signatureLen,
    ] },
]
let data = try JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys])
FileHandle.standardOutput.write(data)
FileHandle.standardOutput.write(Data("\n".utf8))
