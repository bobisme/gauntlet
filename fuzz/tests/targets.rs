//! Static invariant over the libFuzzer targets.
//!
//! `fuzz/src/lib.rs` documents the entry contract, but the binaries under
//! `fuzz/fuzz_targets/` are separate files. This test reads them, so a target
//! that stops calling its shared entry — an empty `fuzz_target!`, or one wired
//! to another target's parser — fails the fast suite even though the crate still
//! compiles and no corpus entry changed.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const TARGETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz_targets");

fn target_sources() -> Vec<(String, String)> {
    let mut paths = fs::read_dir(Path::new(TARGETS))
        .expect("the fuzz target directory exists")
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<PathBuf>>();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            (name, fs::read_to_string(&path).unwrap())
        })
        .collect()
}

fn normalized(source: &str) -> String {
    source.split_whitespace().collect()
}

#[test]
fn every_target_calls_its_own_shared_entry() {
    let mut declared = BTreeSet::new();
    for (name, source) in target_sources() {
        let compact = normalized(&source);
        assert!(
            compact.contains("fuzz_target!("),
            "{name} must define a fuzz target"
        );
        assert_eq!(
            compact.matches("fuzz_target!").count(),
            1,
            "{name} must define exactly one fuzz target"
        );
        assert_eq!(
            compact.matches("scourge_parser_fuzz::").count(),
            1,
            "{name} must call exactly one shared entry"
        );
        assert!(
            compact.contains(&format!("scourge_parser_fuzz::{name}(input)")),
            "{name} must call its own shared entry with the fuzzer input"
        );
        // The call must be inside the target body, not a stray statement.
        let macro_at = compact.find("fuzz_target!(").unwrap();
        let call_at = compact.find("scourge_parser_fuzz::").unwrap();
        assert!(
            macro_at < call_at,
            "{name} must call the entry inside fuzz_target!"
        );
        declared.insert(name);
    }

    let registered = scourge_parser_fuzz::ENTRIES
        .iter()
        .map(|(target, _)| (*target).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        declared, registered,
        "every target file must be a registered shared entry and the reverse"
    );
}

#[test]
fn every_registered_entry_has_a_corpus_and_a_stage_contract() {
    for (target, _) in scourge_parser_fuzz::ENTRIES {
        assert!(
            scourge_parser_fuzz::stages(target).is_some(),
            "{target} has no entry contract"
        );
        let seeds = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(target);
        let count = fs::read_dir(&seeds)
            .unwrap_or_else(|error| panic!("{target} has no seed corpus: {error}"))
            .count();
        assert!(count > 0, "{target} has an empty seed corpus");
    }
}
