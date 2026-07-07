# pq-crypto-rs

Pure-Rust post-quantum crypto core for the Android side of the Elabify/Musnad
stack: **ML-DSA-65** signatures and the **X-Wing** hybrid KEM, exposed to Kotlin
via UniFFI.

It exists so Android produces **byte-identical** ML-DSA outputs to iOS, which uses
Apple CryptoKit's native ML-DSA-65. The cross-platform contract is a shared KAT
corpus (`test-vectors/`): the same seed must yield the same public key, the same
deterministic signature, and the same verify result on Android (this crate),
iOS (CryptoKit), and the TypeScript/reference path. PQClean was dropped in favour
of the RustCrypto implementations (ADR/F0).

## What's here

```
pq-crypto-rs/
   ├── pq-crypto-core   ←  Rust crate (ML-DSA-65 + X-Wing), UniFFI-exported
   ├── android          ←  Kotlin bindings + AAR build
   ├── test-vectors     ←  KAT corpus (the cross-platform byte-equivalence contract)
   └── tools            ←  KAT generators
```

iOS does not consume this crate: it uses Apple CryptoKit's `MLDSA65` directly
(iOS 26+). This crate is the Android equivalent, validated equal to CryptoKit by
the KATs.

## Cryptography

- **ML-DSA-65** (FIPS 204) via the RustCrypto [`ml-dsa`](https://crates.io/crates/ml-dsa)
  crate. Key generation, signing, and verification are seed-deterministic so the
  same 32-byte seed reproduces the same on-chain public key across platforms
  (import-by-seed preserves a registered issuer/holder identity).
- **X-Wing** hybrid KEM via the [`x-wing`](https://crates.io/crates/x-wing) crate
  (ML-KEM-768 + X25519), used transport-only for the encrypted PII handoff
  ("Verify & Pay" seal). Proven byte-interoperable with Apple's
  `XWingMLKEM768X25519_SHA256_AES_GCM_256` in both directions.

## Public surface (UniFFI, Kotlin)

- `mldsa65_public_key(seed) -> pubkey`
- `mldsa65_sign(seed, message) -> signature` (deterministic)
- `mldsa65_verify_signature(public_key, signature, message) -> bool`

plus the X-Wing encapsulate/decapsulate seam used by the transport layer.

## Build

Same pattern as the `ledger-*-rs` / `trezor-core-rs` cores: a single Rust crate
compiled to an Android AAR with UniFFI-generated Kotlin bindings (see `android/`).

## Testing

`test-vectors/` is the source of truth. The Rust tests and the Android + iOS +
TypeScript sides all replay the same KAT corpus; a mismatch on any platform is a
build-failing contract break, not a warning.

---

*Mirrors to the public `elabify/maknoon-pq-crypto-rs`. Trust-critical; the KAT
corpus is the guarantee that every platform computes the same PQ crypto.*
