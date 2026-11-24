//! Scourge domain values and frozen JSON contracts.

pub mod canonical;
pub mod domain;
pub mod ids;
mod json_input;
pub mod store;
pub mod wire;

#[cfg(test)]
#[path = "../build_support/registry.rs"]
mod registry;
