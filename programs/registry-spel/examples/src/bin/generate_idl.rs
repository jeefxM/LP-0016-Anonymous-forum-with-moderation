/// Generate IDL JSON for the registry-spel program.
///
/// Usage:
///   cargo run --bin generate_idl > registry-spel-idl.json

spel_framework::generate_idl!("../methods/guest/src/bin/registry_spel.rs");
