use std::{env, fs, path::PathBuf};

#[path = "src/json_input.rs"]
mod json_input;
#[path = "build_support/registry.rs"]
mod registry;

const REGISTRY: &str = "../../docs/contracts/scourge-v1.json";

fn main() {
    println!("cargo:rerun-if-changed={REGISTRY}");
    println!("cargo:rerun-if-changed=src/json_input.rs");
    println!("cargo:rerun-if-changed=build_support/registry.rs");
    let bytes = fs::read(REGISTRY).expect("could not read contract registry");
    let output = registry::generate(&bytes).unwrap_or_else(|error| panic!("{REGISTRY}: {error}"));
    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("wire.rs");
    fs::write(path, output).expect("could not write generated wire types");
}
