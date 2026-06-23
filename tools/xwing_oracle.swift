// CryptoKit X-Wing HPKE oracle for the cross-platform parity test
// (pq-crypto-core/tests/xwing_parity.rs). Proves that the Rust X-Wing HPKE
// interoperates byte-exact with Apple CryptoKit's
// HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256, both directions.
// Run on macOS 26 (CryptoKit ships X-Wing in iOS 26 / macOS 26).
//
//   seal <pk_hex> <info_hex> <pt_hex>            -> "<enc_hex> <sealed_hex>"
//        CryptoKit is the HPKE sender; Rust opens. [Direction B]
//   driveRustSeal <rustcli> <info_hex> <pt_hex>  -> "<opened_pt_hex>"
//        CryptoKit generates the recipient keypair + opens; Rust (via the
//        xwing_cli `seal`) is the sender. [Direction A: the commerce-critical
//        path -- an Android holder seals to the iOS merchant's public key.]
//
// Hex everywhere so it matches the Rust CLI's wire format (no base64 dep).

import Foundation
import CryptoKit

func die(_ m: String) -> Never { FileHandle.standardError.write(Data((m + "\n").utf8)); exit(2) }
func unhex(_ s: String) -> Data {
    let s = s.trimmingCharacters(in: .whitespacesAndNewlines)
    var out = Data(capacity: s.count / 2)
    var idx = s.startIndex
    while idx < s.endIndex {
        let next = s.index(idx, offsetBy: 2)
        guard let b = UInt8(s[idx..<next], radix: 16) else { die("bad hex") }
        out.append(b); idx = next
    }
    return out
}
func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

let suite: HPKE.Ciphersuite = .XWingMLKEM768X25519_SHA256_AES_GCM_256
let args = CommandLine.arguments
guard args.count >= 2 else { die("usage: seal|driveRustSeal ...") }

switch args[1] {
case "seal":
    let pkRaw = unhex(args[2]); let info = unhex(args[3]); let pt = unhex(args[4])
    let pk = try XWingMLKEM768X25519.PublicKey(rawRepresentation: pkRaw)
    var sender = try HPKE.Sender(recipientKey: pk, ciphersuite: suite, info: info)
    let sealed = try sender.seal(pt)
    print("\(hex(sender.encapsulatedKey)) \(hex(sealed))")

case "driveRustSeal":
    let rustcli = args[2]; let infoHex = args[3]; let ptHex = args[4]
    let info = unhex(infoHex)
    // 1. CryptoKit generates the recipient (merchant) keypair.
    let sk = try XWingMLKEM768X25519.PrivateKey.generate()
    let pkHex = hex(sk.publicKey.rawRepresentation)
    // 2. Rust seals to that public key.
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: rustcli)
    proc.arguments = ["seal", pkHex, infoHex, ptHex]
    let outPipe = Pipe(); let errPipe = Pipe()
    proc.standardOutput = outPipe; proc.standardError = errPipe
    try proc.run(); proc.waitUntilExit()
    guard proc.terminationStatus == 0 else {
        let e = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        die("rust seal failed: \(e)")
    }
    let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)!
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let parts = out.split(separator: " ")
    guard parts.count == 2 else { die("rust seal bad output: \(out)") }
    let enc = unhex(String(parts[0])); let sealed = unhex(String(parts[1]))
    // 3. CryptoKit opens the Rust-sealed envelope.
    var recip = try HPKE.Recipient(privateKey: sk, ciphersuite: suite, info: info, encapsulatedKey: enc)
    let opened = try recip.open(sealed)
    print(hex(opened))

default:
    die("unknown subcommand \(args[1])")
}
