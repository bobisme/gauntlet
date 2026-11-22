#!/usr/bin/env bash
# Build into this project, without writing into the source checkouts.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source_root=${SCOURGE_SOURCE_ROOT:-"$HOME/src"}
export CARGO_TARGET_DIR="$root/.stack-target"
cargo build --locked --manifest-path "$source_root/teapot/Cargo.toml" -p teapot --bin teapot
cargo build --locked --manifest-path "$source_root/hallpass/Cargo.toml" --bin hallpass
cargo build --locked --manifest-path "$source_root/playpen/Cargo.toml" --bin playpen
