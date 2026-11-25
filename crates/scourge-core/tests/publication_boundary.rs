use scourge_core::{
    canonical::Sha256Digest,
    domain::Run,
    store::{Store, StoreError},
    wire::{Artifact, OracleResult, Reproduction, RunState},
};

#[test]
fn a_fresh_unkeyed_finalized_run_cannot_enter_the_verification_chain() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(directory.path().join("state.sqlite3")).unwrap();
    let engagement = "public-boundary".parse().unwrap();
    let digest = Sha256Digest::of(b"manifest fixture");
    let manifest = Artifact {
        artifact_id: "art_manifest".parse().unwrap(),
        digest: digest.clone(),
    };
    store
        .append_manifest(&engagement, &manifest, &digest)
        .unwrap();
    let head = store.checkpoint(&engagement).unwrap();
    let revision = store.revision().unwrap();

    let mut run = Run::declare(engagement.clone(), Sha256Digest::of(b"experiment"));
    run.state = RunState::Finalized;
    run.oracle_result = Some(OracleResult::True);
    run.reproduction = Reproduction::Reproduced;
    for previous_revision in [None, Some(revision)] {
        assert!(matches!(
            store.record_run(&run, previous_revision),
            Err(StoreError::Conflict)
        ));
        assert!(store.recover_run(&run.id).is_err());
        assert!(store.publication(&run.id).unwrap().is_none());
        assert_eq!(store.revision().unwrap(), revision);
        assert_eq!(store.checkpoint(&engagement).unwrap(), head);
    }
}
