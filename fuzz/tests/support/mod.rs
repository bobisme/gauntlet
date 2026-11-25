//! Corpus replay shared by the regression suite and the mutation witnesses.
//!
//! Both test binaries include this module, so the check that an entry reaches
//! its parsers and the mutation guard that replaces an entry with a no-op run
//! exactly the same code.

use std::{fmt, fs, path::Path};

use scourge_parser_fuzz::{Decision, Entry, MAX_INPUT_BYTES, Outcome, stages};

pub const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus");

pub fn seed(target: &str, name: &str) -> Vec<u8> {
    fs::read(Path::new(CORPUS).join(target).join(name)).unwrap_or_else(|error| {
        panic!("corpus seed {target}/{name} must exist: {error}");
    })
}

/// Every seed of one target, sorted by name.
#[must_use]
pub fn seeds(target: &str) -> Vec<(String, Vec<u8>)> {
    let mut paths = fs::read_dir(Path::new(CORPUS).join(target))
        .unwrap_or_else(|error| panic!("{target} must have a seed corpus: {error}"))
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let bytes = fs::read(&path).unwrap();
            (name, bytes)
        })
        .collect()
}

/// The shared entry registered for one target.
#[must_use]
pub fn entry(target: &str) -> Option<Entry> {
    scourge_parser_fuzz::ENTRIES
        .iter()
        .find(|(name, _)| *name == target)
        .map(|(_, entry)| *entry)
}

/// Replay every seed of `target` through `entry`.
///
/// The replay fails when a seed is oversized, when the entry records nothing,
/// when its stage trace is not the one [`stages`] declares for the target, or
/// when it rejects without a typed error. An entry that returns immediately,
/// calls another target's parsers or silently stops calling one of them cannot
/// pass, which is the mutation guard `witnesses.rs` also runs directly.
pub fn replay(target: &str, entry: Entry) -> Result<Vec<(String, Outcome)>, String> {
    let expected = stages(target).ok_or_else(|| format!("unknown fuzz target {target}"))?;
    let mut observed = Vec::new();
    for (name, bytes) in seeds(target) {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(format!("corpus seed {target}/{name} exceeds the input cap"));
        }
        let outcome = entry(&bytes);
        if outcome.is_empty() {
            return Err(format!(
                "{target}/{name}: the entry recorded no decision, so it never reached a parser"
            ));
        }
        let visited = outcome.stages().collect::<Vec<_>>();
        if visited != expected {
            return Err(format!(
                "{target}/{name}: entry visited {visited:?}, the entry contract is {expected:?}"
            ));
        }
        for (stage, decision) in outcome.decisions() {
            if let Decision::Rejected(error) = decision
                && error.is_empty()
            {
                return Err(format!(
                    "{target}/{name}: {stage} rejected without a typed error"
                ));
            }
        }
        observed.push((name, outcome));
    }
    Ok(observed)
}

/// The outcome one entry recorded for one named seed.
#[must_use]
pub fn outcome(target: &str, name: &str) -> Outcome {
    let entry = entry(target).unwrap_or_else(|| panic!("unknown fuzz target {target}"));
    entry(&seed(target, name))
}

/// The decision one stage recorded, for exact assertions.
#[must_use]
pub fn decision<'a>(outcome: &'a Outcome, stage: &str) -> &'a Decision {
    outcome.get(stage).unwrap_or_else(|| {
        panic!(
            "no {stage} stage in {:?}",
            outcome.stages().collect::<Vec<_>>()
        )
    })
}

/// A typed rejection, as the entry records it.
#[must_use]
pub fn rejected(error: impl fmt::Display) -> Decision {
    Decision::Rejected(error.to_string())
}
