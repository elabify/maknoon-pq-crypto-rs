// Wrapper binary so `cargo run --bin uniffi-bindgen` generates the
// Swift / Kotlin glue from the crate's own scaffolding (proc-macro
// mode). Same pattern as the ledger-*-rs cores.
fn main() {
    uniffi::uniffi_bindgen_main()
}
