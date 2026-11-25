//! Scourge domain values and frozen JSON contracts.

pub mod canonical;
mod declaration;
pub mod domain;
pub mod engagement;
pub mod evidence;
pub mod ids;
mod json_input;
mod operations;
pub mod planning;
pub mod policy;
pub mod preflight;
pub mod request;
pub mod response;
pub mod rounds;
pub mod store;
pub mod teapot;
pub mod template;
mod toml_input;
pub mod verification;
pub mod wire;
pub mod workspace;

pub use declaration::{DeclarationError, DeclarationIssue, is_schema_stanza};

#[cfg(test)]
pub(crate) mod execution_effects {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone, Debug, Default)]
    pub(crate) struct ExecutionEffects(Arc<Counters>);

    #[derive(Debug, Default)]
    struct Counters {
        store_writer: AtomicUsize,
        evidence_access: AtomicUsize,
        evidence_capture: AtomicUsize,
        evidence_attachment: AtomicUsize,
        evidence_finalize: AtomicUsize,
        teapot_process: AtomicUsize,
    }

    #[derive(Debug, Default, PartialEq, Eq)]
    pub(crate) struct Snapshot {
        pub store_writer: usize,
        pub evidence_access: usize,
        pub evidence_capture: usize,
        pub evidence_attachment: usize,
        pub evidence_finalize: usize,
        pub teapot_process: usize,
    }

    impl ExecutionEffects {
        pub(crate) fn store_writer(&self) {
            self.0.store_writer.fetch_add(1, Ordering::Relaxed);
        }

        pub(crate) fn evidence_access(&self) {
            self.0.evidence_access.fetch_add(1, Ordering::Relaxed);
        }

        pub(crate) fn evidence_capture(&self) {
            self.0.evidence_capture.fetch_add(1, Ordering::Relaxed);
        }

        pub(crate) fn evidence_attachment(&self) {
            self.0.evidence_attachment.fetch_add(1, Ordering::Relaxed);
        }

        pub(crate) fn evidence_finalize(&self) {
            self.0.evidence_finalize.fetch_add(1, Ordering::Relaxed);
        }

        pub(crate) fn teapot_process(&self) {
            self.0.teapot_process.fetch_add(1, Ordering::Relaxed);
        }

        pub(crate) fn snapshot(&self) -> Snapshot {
            Snapshot {
                store_writer: self.0.store_writer.load(Ordering::Relaxed),
                evidence_access: self.0.evidence_access.load(Ordering::Relaxed),
                evidence_capture: self.0.evidence_capture.load(Ordering::Relaxed),
                evidence_attachment: self.0.evidence_attachment.load(Ordering::Relaxed),
                evidence_finalize: self.0.evidence_finalize.load(Ordering::Relaxed),
                teapot_process: self.0.teapot_process.load(Ordering::Relaxed),
            }
        }
    }
}

#[cfg(test)]
#[path = "../build_support/registry.rs"]
mod registry;
