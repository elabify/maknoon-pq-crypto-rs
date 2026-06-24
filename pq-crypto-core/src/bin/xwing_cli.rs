// Dev CLI for the X-Wing HPKE transport, used by the cross-platform parity
// test (tests/xwing_parity.rs) to interoperate with the CryptoKit oracle
// (tools/xwing_oracle.swift). Not shipped in the AAR. Hex in/out (no base64
// dep so the shipped crate stays lean).
//
//   gen                                              -> "<sk_hex> <ek_hex>"
//   seal <ek_hex> <info_hex> <pt_hex>                -> "<enc_hex> <sealed_hex>"
//   open <sk_hex> <info_hex> <enc_hex> <sealed_hex>  -> "<pt_hex>"

use pq_crypto_core::xwing::{
    xwing_open_with_secret, xwing_public_key_from_secret, xwing_seal_deterministic,
};

fn rand64() -> [u8; 64] {
    let mut b = [0u8; 64];
    getrandom::getrandom(&mut b).expect("getrandom");
    b
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("hex arg")
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("gen") => {
            let mut sk = [0u8; 32];
            getrandom::getrandom(&mut sk).expect("getrandom");
            let pk = xwing_public_key_from_secret(&sk);
            println!("{} {}", hex::encode(sk), hex::encode(&pk));
        }
        Some("seal") => {
            let (ek, info, pt) = (h(&a[2]), h(&a[3]), h(&a[4]));
            let (enc, sealed) = xwing_seal_deterministic(&ek, &info, &pt, &rand64()).expect("seal");
            println!("{} {}", hex::encode(&enc), hex::encode(&sealed));
        }
        Some("open") => {
            let (sk_v, info, enc, sealed) = (h(&a[2]), h(&a[3]), h(&a[4]), h(&a[5]));
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&sk_v);
            match xwing_open_with_secret(&sk, &enc, &info, &sealed) {
                Ok(pt) => println!("{}", hex::encode(&pt)),
                Err(e) => {
                    eprintln!("open failed: {e}");
                    std::process::exit(2);
                }
            }
        }
        _ => {
            eprintln!("usage: gen | seal <ek_hex> <info_hex> <pt_hex> | open <sk_hex> <info_hex> <enc_hex> <sealed_hex>");
            std::process::exit(1);
        }
    }
}
