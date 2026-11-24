//! Scourge domain values and frozen JSON contracts.

pub mod canonical;
mod declaration;
pub mod domain;
pub mod engagement;
pub mod ids;
mod json_input;
pub mod policy;
pub mod request;
pub mod response;
pub mod store;
pub mod teapot;
pub mod template;
mod toml_input;
pub mod wire;
pub mod workspace;

pub use declaration::{DeclarationError, DeclarationIssue};

#[cfg(test)]
#[path = "../build_support/registry.rs"]
mod registry;
