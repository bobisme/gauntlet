use std::{
    panic::AssertUnwindSafe,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::*;
use crate::{
    domain::RunStep,
    engagement::{EngagementDraft, PassPin},
    ids::{LeadId, RequestKey, RunId},
    preflight::{self, PreflightDeclaration, PreflightError},
    request::Invocation,
    template::{Claim, EngagementPin, SlotValue, Templates},
    wire::{Cleanup, Completeness, Effect, ErrorCode, Flow, OracleResult, RunFlag, RunState},
};
use read::{ReadStore, RecoverySelector};

fn open() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("state.sqlite3")).unwrap();
    (dir, store)
}

fn raw(dir: &TempDir) -> Connection {
    Connection::open(dir.path().join("state.sqlite3")).unwrap()
}

fn scope(engagement: &str, binding: &str) -> RequestScope {
    RequestScope::new(engagement.parse().unwrap(), binding.parse().unwrap())
}

fn normalized(command: &str, arguments: Value) -> NormalizedInput {
    Invocation::new(command, arguments).normalize().unwrap()
}

fn verify_input(lead: &str) -> NormalizedInput {
    normalized("verify", json!({ "lead_id": lead }))
}

fn when(engagement: &EngagementId) -> Run {
    Run::declare(engagement.clone(), Sha256Digest::of(b"experiment"))
}

fn manifest() -> Artifact {
    Artifact {
        artifact_id: "a1".parse().unwrap(),
        digest: Sha256Digest::of(b"manifest"),
    }
}

fn lead_revision(lead: &LeadId, revision: u64, text: &str) -> LeadRevision {
    LeadRevision {
        lead_id: lead.clone(),
        revision,
        text: text.parse().unwrap(),
        class: None,
        property: None,
        slots: Default::default(),
        proposed_policy: None,
        origin: crate::domain::LeadOrigin::Local,
        source_ref: None,
        endpoint: None,
        flow_ids: Vec::new(),
        producer_confidence: None,
    }
}

/// A usable engagement: one manifest revision and one lead revision.
fn seed(store: &mut Store, engagement: &EngagementId) -> LeadId {
    let asset = manifest();
    store
        .append_manifest(engagement, &asset, &asset.digest)
        .unwrap();
    let lead = LeadId::generate();
    store
        .append_lead_revision(engagement, &lead_revision(&lead, 1, "first"))
        .unwrap();
    lead
}

/// Append lead revisions 2..=last through the store's ordinary compare-and-set.
fn edit_lead(store: &mut Store, engagement: &EngagementId, lead: &LeadId, last: u64) {
    for revision in 2..=last {
        store
            .append_lead_revision(engagement, &lead_revision(lead, revision, "edit"))
            .unwrap();
    }
}

fn audit_state(s: &Store) -> (u64, i64) {
    (
        s.revision().unwrap(),
        s.db.query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))
            .unwrap(),
    )
}

fn accept_events(s: &Store) -> i64 {
    s.db.query_row(
        "SELECT count(*) FROM audit_events WHERE operation='request.accept'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

/// Run and request-key row counts, in that order.
fn row_counts(s: &Store) -> (i64, i64) {
    s.db.query_row(
        "SELECT (SELECT count(*) FROM runs), (SELECT count(*) FROM request_keys)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap()
}

fn verification_draft(max_runs: u64) -> EngagementDraft {
    let declaration = include_str!("../../../../fixtures/target/schema-examples/engagement.toml");
    EngagementDraft::parse_toml(
        declaration
            .replace(
                "max_verify_runs = 50",
                &format!("max_verify_runs = {max_runs}"),
            )
            .as_bytes(),
    )
    .unwrap()
}

fn verification_manifest(max_runs: u64) -> ManifestRevision {
    let draft = verification_draft(max_runs);
    let reference = draft.settings().pass_ref.clone();
    draft
        .accept(PassPin {
            reference: &reference,
            digest: &Sha256Digest::of(b"pass"),
        })
        .unwrap()
}

fn append_verification_manifest(
    store: &mut Store,
    engagement: &EngagementId,
    manifest: &ManifestRevision,
) -> Artifact {
    let artifact = Artifact {
        artifact_id: format!("manifest-{}", manifest.revision()).parse().unwrap(),
        digest: manifest.digest().clone(),
    };
    store
        .append_manifest(engagement, &artifact, manifest.pass_digest())
        .unwrap();
    artifact
}

pub(super) fn verification_claim(lead: &LeadId, manifest: &ManifestRevision) -> Claim {
    Claim {
        class: "web-authz/private-object-read".parse().unwrap(),
        engagement: EngagementPin {
            revision: manifest.revision(),
            digest: manifest.digest().clone(),
        },
        lead: lead.clone(),
        property: Some("orders".parse().unwrap()),
        lead_slots: [("owner", "alice"), ("other", "bob")]
            .map(|(name, value)| SlotValue {
                name: name.parse().unwrap(),
                value: value.parse().unwrap(),
            })
            .into(),
        overrides: Vec::new(),
    }
}

pub(super) fn verification_lead_revision(
    lead: &LeadId,
    revision: u64,
    text: &str,
    manifest: &ManifestRevision,
) -> LeadRevision {
    let claim = verification_claim(lead, manifest);
    let mut stored = lead_revision(lead, revision, text);
    stored.class = Some(claim.class.as_str().parse().unwrap());
    stored.property = claim
        .property
        .map(|property| property.as_str().parse().unwrap());
    stored.slots = claim
        .lead_slots
        .into_iter()
        .map(|slot| {
            (
                slot.name.as_str().parse().unwrap(),
                Value::String(slot.value.as_str().to_owned()),
            )
        })
        .collect();
    stored
}

pub(super) fn verification_run(
    engagement: &EngagementId,
    claim: &Claim,
    manifest: &ManifestRevision,
) -> Run {
    let (_, digest) = Templates::resolve(claim, manifest)
        .unwrap()
        .ready()
        .unwrap()
        .freeze()
        .unwrap();
    Run::declare(engagement.clone(), digest)
}

pub(super) fn admit_verification(
    store: &mut Store,
    scope: &RequestScope,
    input: &NormalizedInput,
    run: &Run,
    claim: &Claim,
    manifest: &ManifestRevision,
    artifact: &Artifact,
) -> std::result::Result<RunAcceptance, PreflightError> {
    preflight::declare(
        store,
        PreflightDeclaration {
            scope,
            input,
            run,
            claim,
            lead_revision: 1,
            engagement: manifest,
            manifest_artifact: artifact,
        },
    )
    .map(|declaration| declaration.acceptance().clone())
}

#[test]
fn verification_allowance_fences_concurrent_keys_and_replays_exactly() {
    let (dir, mut store) = open();
    let engagement: EngagementId = "limited".parse().unwrap();
    let manifest = verification_manifest(1);
    let artifact = append_verification_manifest(&mut store, &engagement, &manifest);
    let lead = LeadId::generate();
    store
        .append_lead_revision(
            &engagement,
            &verification_lead_revision(&lead, 1, "first", &manifest),
        )
        .unwrap();
    let input = verify_input(lead.as_str());
    let claim = verification_claim(&lead, &manifest);
    let barrier = Barrier::new(2);
    let path = dir.path().join("state.sqlite3");
    let outcomes = thread::scope(|threads| {
        let workers = ["binding-one", "binding-two"].map(|binding| {
            let run = verification_run(&engagement, &claim, &manifest);
            let scope = scope(engagement.as_str(), binding);
            let (barrier, path, input, claim, manifest, artifact) =
                (&barrier, &path, &input, &claim, &manifest, &artifact);
            threads.spawn(move || {
                let mut connection = Store::open(path).unwrap();
                barrier.wait();
                let outcome = admit_verification(
                    &mut connection,
                    &scope,
                    input,
                    &run,
                    claim,
                    manifest,
                    artifact,
                );
                (scope, outcome)
            })
        });
        workers.map(|worker| worker.join().unwrap())
    });
    let mut winner = None;
    let mut refusals = 0;
    for (scope, outcome) in outcomes {
        match outcome {
            Ok(accepted) => assert!(winner.replace((scope, accepted)).is_none()),
            Err(refusal) => {
                assert_eq!(refusal.code(), ErrorCode::BudgetRefused);
                refusals += 1;
            }
        }
    }
    assert_eq!(refusals, 1);
    let (winner_scope, accepted) = winner.unwrap();
    let before_replay = audit_state(&store);
    let mut retry = when(&engagement);
    retry.request_key = accepted.run.request_key.clone();
    assert_eq!(
        admit_verification(
            &mut store,
            &winner_scope,
            &input,
            &retry,
            &claim,
            &manifest,
            &artifact
        )
        .unwrap(),
        accepted
    );
    let different = normalized("verify", json!({ "lead_id": lead, "rounds": 3 }));
    assert!(matches!(
        admit_verification(
            &mut store,
            &winner_scope,
            &different,
            &retry,
            &claim,
            &manifest,
            &artifact
        ),
        Err(PreflightError::Store(StoreError::IdempotencyKeyReused))
    ));
    retry.experiment_digest = Sha256Digest::of(b"different experiment");
    assert_eq!(
        admit_verification(
            &mut store,
            &winner_scope,
            &input,
            &retry,
            &claim,
            &manifest,
            &artifact
        )
        .unwrap(),
        accepted,
    );
    assert_eq!(audit_state(&store), before_replay);
    assert_eq!(row_counts(&store), (1, 1));
}

#[test]
fn identical_verification_writers_share_one_receipt_at_the_last_slot() {
    let (dir, mut store) = open();
    let scope = scope("limited", "one");
    let manifest = verification_manifest(1);
    let artifact = append_verification_manifest(&mut store, &scope.engagement, &manifest);
    let lead = LeadId::generate();
    store
        .append_lead_revision(
            &scope.engagement,
            &verification_lead_revision(&lead, 1, "first", &manifest),
        )
        .unwrap();
    let input = verify_input(lead.as_str());
    let claim = verification_claim(&lead, &manifest);
    let run = verification_run(&scope.engagement, &claim, &manifest);
    let barrier = Barrier::new(2);
    let path = dir.path().join("state.sqlite3");
    let before = audit_state(&store);
    let [first, second] = thread::scope(|threads| {
        let accept = || {
            let mut connection = Store::open(&path).unwrap();
            barrier.wait();
            admit_verification(
                &mut connection,
                &scope,
                &input,
                &run,
                &claim,
                &manifest,
                &artifact,
            )
            .unwrap()
        };
        let first = threads.spawn(accept);
        let second = threads.spawn(accept);
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(first, second);
    assert_eq!(first.receipt, before.0 + 1);
    assert_eq!(audit_state(&store), (before.0 + 1, before.1 + 1));
    assert_eq!(row_counts(&store), (1, 1));
}

#[test]
fn historical_verification_keeps_existing_recovery_steps_but_cannot_start_another() {
    let (dir, mut store) = open();
    let scope = scope("historical", "one");
    let lead = seed(&mut store, &scope.engagement);
    let mut run = when(&scope.engagement);
    run.steps.push(RunStep {
        number: 1,
        step: "historical.intent".parse().unwrap(),
        request_digest: Sha256Digest::of(b"historical intent"),
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        flows: Vec::new(),
    });
    let input = verify_input(lead.as_str());
    // Seed the older database representation, including the pre-fence
    // receipt and its existing exact claim, through fixture SQL.
    let tx = store.db.transaction().unwrap();
    create_run(&tx, &run).unwrap();
    let receipt = advance(&tx, REQUEST_ACCEPT, run.id.as_str()).unwrap();
    tx.execute(
        "INSERT INTO request_keys
         (key, engagement_id, binding, command, input, input_digest, run_id,
          receipt_revision, lead_id, lead_revision, engagement_revision)
         VALUES (?1, ?2, ?3, 'verify', ?4, ?5, ?6, ?7, ?8, 1, 1)",
        params![
            run.request_key.as_str(),
            scope.engagement.as_str(),
            scope.binding.as_str(),
            String::from_utf8(input.to_bytes().unwrap()).unwrap(),
            input.digest().unwrap().as_str(),
            run.id.as_str(),
            integer(receipt).unwrap(),
            lead.as_str(),
        ],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO run_conflict_sets (run_id, set_digest, claim_kind) VALUES (?, 'historical', 'exact')",
        [run.id.as_str()],
    ).unwrap();
    tx.commit().unwrap();
    drop(store);
    let path = dir.path().join("state.sqlite3");
    let mut store = Store::open(&path).unwrap();
    let reader = ReadStore::open(&path).unwrap();
    assert!(
        reader
            .recover(&scope, RecoverySelector::Run(&run.id))
            .unwrap()
            .has_unresolved_dispatch()
    );
    drop(reader);

    let mut step = run.steps[0].clone();
    step.effects = Some(Effect::None);
    store.record_step(&run.id, &step).unwrap();
    let replay = store
        .reopen_request(&scope, &run.request_key, &input)
        .unwrap();
    assert_eq!(replay.receipt, receipt);
    assert_eq!(replay.run.steps, [step.clone()]);

    let before = audit_state(&store);
    step.number = 2;
    assert!(matches!(
        store.record_step(&run.id, &step),
        Err(StoreError::Conflict)
    ));
    let mut updated = replay.run;
    updated.steps.push(step);
    assert!(matches!(
        store.record_run(&updated, Some(receipt)),
        Err(StoreError::Conflict)
    ));
    assert_eq!(audit_state(&store), before);
    assert_eq!(store.recover_run(&run.id).unwrap().steps.len(), 1);
}

#[test]
fn fresh_metadata_requests_require_pristine_run_state() {
    let (_dir, mut store) = open();
    let scope = scope("local", "one");
    let lead = seed(&mut store, &scope.engagement);
    let before = audit_state(&store);
    let inputs = [verify_input(lead.as_str()), normalized("other", json!({}))];
    let step = RunStep {
        number: 1,
        step: "example.intent".parse().unwrap(),
        request_digest: Sha256Digest::of(b"step"),
        flow_id_floor: None,
        instrument_reference: None,
        effects: Some(Effect::Observed),
        flows: Vec::new(),
    };
    for input in inputs {
        let initial = when(&scope.engagement);
        let mut bundled = initial.clone();
        bundled.steps.push(step.clone());
        let mut running = initial.clone();
        running.state = RunState::Running;
        for run in [vec![bundled, running], non_pristine_outcomes(&initial)].concat() {
            assert!(matches!(
                store.declare_metadata_fixture(&scope, &input, &run),
                Err(StoreError::Conflict)
            ));
            assert!(
                store
                    .find_request(&scope, &run.request_key)
                    .unwrap()
                    .is_none()
            );
        }
    }
    assert_eq!(row_counts(&store), (0, 0));
    assert_eq!(audit_state(&store), before);
}

fn non_pristine_outcomes(initial: &Run) -> Vec<Run> {
    let mutations: [fn(&mut Run); 6] = [
        |run| run.effects = Effect::Unknown,
        |run| run.effects = Effect::Observed,
        |run| run.oracle_result = Some(OracleResult::True),
        |run| run.cleanup = Cleanup::Unknown,
        |run| run.reproduction = Reproduction::Reproduced,
        |run| run.flags.push(RunFlag::ReconciliationRequired),
    ];
    mutations
        .into_iter()
        .map(|mutate| {
            let mut run = initial.clone();
            mutate(&mut run);
            run
        })
        .collect()
}

#[test]
fn step_free_run_updates_cannot_fabricate_dispatch_or_outcomes() {
    let (dir, mut store) = open();
    let scope = scope("local", "one");
    let (lead, manifest, artifact) = seed_recoverable_verification(&mut store, &scope);
    let input = verify_input(lead.as_str());
    let claim = verification_claim(&lead, &manifest);
    let metadata = verification_run(&scope.engagement, &claim, &manifest);
    let fenced = verification_run(&scope.engagement, &claim, &manifest);
    let other = when(&scope.engagement);
    let metadata = store
        .declare_metadata_fixture(&scope, &input, &metadata)
        .unwrap();
    let other = store
        .declare_metadata_fixture(&scope, &normalized("other", json!({})), &other)
        .unwrap();
    let keys = BTreeSet::from(["resource:fenced".to_owned()]);
    for accepted in [&metadata, &other] {
        assert!(matches!(
            store.claim_conflicts(&accepted.run.id, &keys),
            Err(StoreError::Conflict)
        ));
    }
    let fenced = admit_verification(
        &mut store, &scope, &input, &fenced, &claim, &manifest, &artifact,
    )
    .unwrap();
    store.claim_conflicts(&fenced.run.id, &keys).unwrap();
    let reader = ReadStore::open(&dir.path().join("state.sqlite3")).unwrap();
    let before = (audit_state(&store), row_counts(&store));
    for accepted in [metadata, other, fenced] {
        let mut refusal = accepted.run.clone();
        refusal.state = RunState::Finalized;
        refusal.flags.push(RunFlag::FailedBeforeStart);
        for update in non_pristine_outcomes(&refusal) {
            assert!(matches!(
                store.record_run(&update, Some(accepted.receipt)),
                Err(StoreError::Conflict)
            ));
        }
        let recovered = reader
            .recover(&scope, RecoverySelector::Run(&accepted.run.id))
            .unwrap();
        assert_eq!(recovered.acceptance, accepted);
        assert!(!recovered.has_unresolved_dispatch());
        reader
            .snapshot(|snapshot| {
                let detail = snapshot
                    .scope(scope.engagement.clone())?
                    .run(&accepted.run.id)?;
                assert_eq!(detail.view.effects, Effect::None);
                assert_eq!(detail.view.run.oracle_result, None);
                Ok(())
            })
            .unwrap();
    }
    assert_eq!((audit_state(&store), row_counts(&store)), before);
}

#[test]
fn verification_allowance_counts_older_requests_across_amendments_only_in_its_engagement() {
    let (_dir, mut store) = open();
    let original_scope = scope("limited", "original");
    let engagement = &original_scope.engagement;
    let original = verification_manifest(1);
    append_verification_manifest(&mut store, engagement, &original);
    let lead = LeadId::generate();
    store
        .append_lead_revision(
            engagement,
            &verification_lead_revision(&lead, 1, "first", &original),
        )
        .unwrap();
    let input = verify_input(lead.as_str());
    // A key already in the store before the fenced admission API was used.
    store
        .declare_metadata_fixture(&original_scope, &input, &when(engagement))
        .unwrap();
    let amended = original
        .amend(
            verification_draft(1),
            PassPin {
                reference: &original.settings().pass_ref,
                digest: original.pass_digest(),
            },
        )
        .unwrap();
    let artifact = append_verification_manifest(&mut store, engagement, &amended);
    let after_amendment = audit_state(&store);
    let claim = verification_claim(&lead, &amended);
    let result = admit_verification(
        &mut store,
        &scope(engagement.as_str(), "different-binding"),
        &input,
        &verification_run(engagement, &claim, &amended),
        &claim,
        &amended,
        &artifact,
    );
    assert!(matches!(
        result,
        Err(PreflightError::Store(StoreError::VerifyBudgetRefused))
    ));
    assert_eq!(audit_state(&store), after_amendment);
    assert_eq!(row_counts(&store), (1, 1));

    let independent = scope("independent", "original");
    let independent_asset =
        append_verification_manifest(&mut store, &independent.engagement, &original);
    let independent_lead = LeadId::generate();
    store
        .append_lead_revision(
            &independent.engagement,
            &verification_lead_revision(&independent_lead, 1, "first", &original),
        )
        .unwrap();
    store
        .declare_metadata_fixture(
            &independent,
            &normalized("other", json!({})),
            &when(&independent.engagement),
        )
        .unwrap();
    let claim = verification_claim(&independent_lead, &original);
    admit_verification(
        &mut store,
        &independent,
        &verify_input(independent_lead.as_str()),
        &verification_run(&independent.engagement, &claim, &original),
        &claim,
        &original,
        &independent_asset,
    )
    .unwrap();
    assert_eq!(row_counts(&store), (3, 3));
}

#[test]
fn experiment_artifact_links_only_with_fenced_claim_and_is_idempotent() {
    let (dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let (lead, manifest, manifest_artifact) = seed_recoverable_verification(&mut store, &scope);
    let input = verify_input(lead.as_str());
    let claim = verification_claim(&lead, &manifest);
    let run = verification_run(&scope.engagement, &claim, &manifest);
    admit_verification(
        &mut store,
        &scope,
        &input,
        &run,
        &claim,
        &manifest,
        &manifest_artifact,
    )
    .unwrap();

    let artifact = Artifact {
        artifact_id: "art_experiment".parse().unwrap(),
        digest: run.experiment_digest.clone(),
    };
    assert!(matches!(
        store.link_experiment(&run.id, &artifact),
        Err(StoreError::Conflict)
    ));
    store
        .claim_conflicts(&run.id, &BTreeSet::from(["resource:linked".to_owned()]))
        .unwrap();
    let linked = store.link_experiment(&run.id, &artifact).unwrap();
    let settled = audit_state(&store);
    assert_eq!(store.link_experiment(&run.id, &artifact).unwrap(), linked);
    assert_eq!(audit_state(&store), settled);

    let reopened = store
        .reopen_request(&scope, &run.request_key, &input)
        .unwrap();
    assert_eq!(reopened.run, run);
    let reader = read::ReadStore::open(&dir.path().join("state.sqlite3")).unwrap();
    reader
        .snapshot(|snapshot| {
            let detail = snapshot.scope(scope.engagement.clone())?.run(&run.id)?;
            assert_eq!(detail.experiment_digest, artifact.digest);
            assert_eq!(
                detail.experiment_artifact_id,
                Some(artifact.artifact_id.clone())
            );
            Ok(())
        })
        .unwrap();

    for conflict in [
        Artifact {
            artifact_id: "art_other".parse().unwrap(),
            digest: artifact.digest.clone(),
        },
        Artifact {
            artifact_id: artifact.artifact_id.clone(),
            digest: Sha256Digest::of(b"wrong experiment"),
        },
    ] {
        assert!(matches!(
            store.link_experiment(&run.id, &conflict),
            Err(StoreError::Conflict)
        ));
        assert_eq!(audit_state(&store), settled);
    }

    let legacy = when(&scope.engagement);
    store.seed_historical_run_fixture(&legacy).unwrap();
    assert!(matches!(
        store.link_experiment(
            &legacy.id,
            &Artifact {
                artifact_id: "art_legacy".parse().unwrap(),
                digest: legacy.experiment_digest.clone(),
            },
        ),
        Err(StoreError::SelectorNotFound)
    ));
}

/// The durable run columns a declaration must never rewrite.
fn run_row(s: &Store, id: &RunId) -> (String, String, String, Option<String>, String, String) {
    s.db.query_row(
        "SELECT state, flags, effects, oracle_result, reproduction, cleanup FROM runs WHERE id=?",
        [id.as_str()],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        },
    )
    .unwrap()
}

#[test]
fn a_replay_compares_input_before_resolving_another_selector_revision() {
    let (_dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let engagement = scope.engagement.clone();
    seed(&mut store, &engagement);
    let asset = manifest();
    store
        .append_manifest(&engagement, &asset, &asset.digest)
        .unwrap();
    let lead = LeadRevision {
        lead_id: LeadId::generate(),
        revision: 1,
        text: "first".parse().unwrap(),
        class: None,
        property: None,
        slots: Default::default(),
        proposed_policy: None,
        origin: crate::domain::LeadOrigin::Local,
        source_ref: None,
        endpoint: None,
        flow_ids: Vec::new(),
        producer_confidence: None,
    };
    store.append_lead_revision(&engagement, &lead).unwrap();

    // A null selector is resolved once, on first acceptance, and snapshotted.
    let input = normalized("verify", json!({ "lead_id": lead.lead_id.as_str() }));
    let run = when(&engagement);
    let key = run.request_key.clone();
    let acceptance = store
        .declare_metadata_fixture(&scope, &input, &run)
        .unwrap();
    assert_eq!(acceptance.lead_revision, Some(1));
    assert_eq!(acceptance.engagement_revision, 2);
    let settled = audit_state(&store);

    // A later lead edit does not move the snapshot and does not change what the
    // key matches. Naming the newly current revision is different input.
    let mut edit = lead.clone();
    edit.revision = 2;
    store.append_lead_revision(&engagement, &edit).unwrap();
    assert_eq!(
        store
            .find_request(&scope, &key)
            .unwrap()
            .unwrap()
            .lead_revision,
        Some(1)
    );
    let explicit = normalized(
        "verify",
        json!({ "lead_id": edit.lead_id.as_str(), "lead_revision": 2 }),
    );
    assert!(matches!(
        store.reopen_request(&scope, &key, &explicit),
        Err(StoreError::IdempotencyKeyReused)
    ));
    let replay = store.reopen_request(&scope, &key, &input).unwrap();
    assert_eq!(replay, acceptance);
    assert_eq!(audit_state(&store).1, settled.1 + 1);
}

#[test]
fn declare_commits_the_key_and_run_before_the_first_boundary() {
    let (dir, mut store) = open();
    let path = dir.path().join("state.sqlite3");
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let run = when(&scope.engagement);
    let key = run.request_key.clone();
    assert_eq!(row_counts(&store), (0, 0));
    assert!(store.find_request(&scope, &key).unwrap().is_none());

    // The only external action in this test is a local counter. It increments
    // once, after a second connection has observed the committed row, and then
    // the process is killed by a panic.
    let effects = AtomicUsize::new(0);
    let killed = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let acceptance = store
            .declare_metadata_fixture(&scope, &input, &run)
            .unwrap();
        let observer = Store::open(&path).unwrap();
        let durable = observer.find_request(&scope, &key).unwrap().unwrap();
        assert_eq!(durable, acceptance);
        assert!(durable.run.steps.is_empty());
        effects.fetch_add(1, Ordering::SeqCst);
        panic!("simulated kill after the first effect boundary");
    }));
    assert!(killed.is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 1);

    // Nothing before the row: the acceptance is the only committed write, and
    // the lost response reopens that run instead of starting another.
    let mut store = Store::open(&path).unwrap();
    let reopened = store.reopen_request(&scope, &key, &input).unwrap();
    assert_eq!(reopened.run, run);
    assert_eq!(row_counts(&store), (1, 1));
    let committed = audit_state(&store);
    assert_eq!(
        committed.1, 4,
        "schema.migrate, two seed writes, acceptance"
    );
    assert_eq!(accept_events(&store), 1);
    assert_eq!(store.revision().unwrap(), reopened.receipt);
    let operation: String = store
        .db
        .query_row(
            "SELECT operation FROM audit_events WHERE revision=?",
            params![integer(reopened.receipt).unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(operation, "request.accept");
}

#[test]
fn reopen_after_a_lost_response_returns_the_current_run_and_original_receipt() {
    let (dir, mut store) = open();
    let path = dir.path().join("state.sqlite3");
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let run = when(&scope.engagement);
    let key = run.request_key.clone();
    let acceptance = store
        .declare_metadata_fixture(&scope, &input, &run)
        .unwrap();
    assert_eq!(acceptance.run.state, RunState::Declared);
    assert_eq!(acceptance.receipt, store.revision().unwrap());

    // The lost response is recovered from a run that closes before dispatch.
    let mut finalized = run.clone();
    finalized.state = RunState::Finalized;
    finalized.flags.push(RunFlag::FailedBeforeStart);
    store
        .record_run(&finalized, Some(acceptance.receipt))
        .unwrap();
    let settled = audit_state(&store);
    let steps_before = row_counts(&store);

    let reopened = store.reopen_request(&scope, &key, &input).unwrap();
    assert_eq!(reopened.run.id, run.id);
    assert_eq!(reopened.receipt, acceptance.receipt);
    assert_eq!(reopened.run.state, RunState::Finalized);
    assert_eq!(reopened.run.effects, Effect::None);
    assert_eq!(reopened.run.flags, [RunFlag::FailedBeforeStart]);
    assert_eq!(audit_state(&store), settled);
    assert_eq!(row_counts(&store), steps_before);

    // A replay after reopening the file is still the same receipt and state.
    drop(store);
    let mut store = Store::open(&path).unwrap();
    assert_eq!(
        store.reopen_request(&scope, &key, &input).unwrap(),
        reopened
    );
    assert_eq!(store.find_request(&scope, &key).unwrap(), Some(reopened));
    assert_eq!(audit_state(&store), settled);
}

#[test]
fn the_same_key_with_different_normalized_input_is_a_typed_conflict() {
    let (_dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let run = when(&scope.engagement);
    let key = run.request_key.clone();
    let acceptance = store
        .declare_metadata_fixture(&scope, &input, &run)
        .unwrap();
    let settled = audit_state(&store);

    for other in [
        normalized("verify", json!({ "lead_id": lead.as_str(), "rounds": 3 })),
        normalized("verify", json!({ "lead_id": "L-2" })),
        normalized("report", json!({ "kind": "summary " })),
        normalized("retest", json!({ "finding_id": "L-1" })),
        normalized(
            "report",
            json!({ "kind": "summary", "items": [{"a": 1}, {"a": 2}] }),
        ),
        normalized(
            "report",
            json!({ "kind": "summary", "items": [{"a": 2}, {"a": 1}] }),
        ),
    ] {
        for error in [
            store.reopen_request(&scope, &key, &other).unwrap_err(),
            store
                .declare_metadata_fixture(&scope, &other, &run)
                .unwrap_err(),
        ] {
            assert!(
                matches!(error, StoreError::IdempotencyKeyReused),
                "{other:?}"
            );
            assert_eq!(error.error_code(), ErrorCode::IdempotencyKeyReused);
            assert_eq!(error.error_code().exit_code(), 4);
        }
        assert_eq!(audit_state(&store), settled);
        assert_eq!(
            store.find_request(&scope, &key).unwrap(),
            Some(acceptance.clone())
        );
    }
}

#[test]
fn unknown_and_foreign_keys_get_the_same_answer_and_create_nothing() {
    let (_dir, mut store) = open();
    let owner = scope("local", "workspace:local");
    let foreign_engagement = scope("second", "workspace:local");
    let foreign_binding = scope("local", "workspace:other");
    let lead = seed(&mut store, &owner.engagement);
    let input = verify_input(lead.as_str());
    let run = when(&owner.engagement);
    let acceptance = store
        .declare_metadata_fixture(&owner, &input, &run)
        .unwrap();
    let settled = audit_state(&store);

    let unknown = RequestKey::generate();
    let missing = store.reopen_request(&owner, &unknown, &input).unwrap_err();
    assert!(matches!(missing, StoreError::RequestNotFound));
    for foreign in [&foreign_engagement, &foreign_binding] {
        let error = store
            .reopen_request(foreign, &run.request_key, &input)
            .unwrap_err();
        assert!(matches!(error, StoreError::RequestNotFound));
        assert_eq!(error.error_code(), missing.error_code());
        assert_eq!(error.error_code(), ErrorCode::ObjectNotFound);
        assert_eq!(error.error_code().exit_code(), 3);
        assert_eq!(error.to_string(), missing.to_string());
        assert!(
            store
                .find_request(foreign, &run.request_key)
                .unwrap()
                .is_none()
        );
        // Declaring with another scope's issued key is refused identically and
        // creates nothing: it must not reveal that the key exists elsewhere.
        let mut elsewhere = Run::declare(foreign.engagement.clone(), Sha256Digest::of(b"other"));
        elsewhere.request_key = run.request_key.clone();
        let refused = store
            .declare_metadata_fixture(foreign, &input, &elsewhere)
            .unwrap_err();
        assert!(matches!(refused, StoreError::RequestNotFound));
        assert_eq!(refused.to_string(), missing.to_string());
    }
    assert!(store.find_request(&owner, &unknown).unwrap().is_none());
    assert_eq!(audit_state(&store), settled);
    assert_eq!(row_counts(&store), (1, 1));

    // An identical declaration of an issued key in its own scope is the
    // original acceptance; it never starts a second run.
    let mut reused = Run::declare(owner.engagement.clone(), Sha256Digest::of(b"other"));
    reused.request_key = run.request_key.clone();
    assert_eq!(
        store
            .declare_metadata_fixture(&owner, &input, &reused)
            .unwrap(),
        acceptance
    );
    assert_eq!(audit_state(&store), settled);
    assert_eq!(row_counts(&store), (1, 1));
    assert_eq!(accept_events(&store), 1);
}

#[test]
fn stale_lead_edits_report_a_typed_revision_conflict() {
    let (_dir, mut store) = open();
    let engagement: EngagementId = "local".parse().unwrap();
    let asset = manifest();
    store
        .append_manifest(&engagement, &asset, &asset.digest)
        .unwrap();
    let mut lead = LeadRevision {
        lead_id: LeadId::generate(),
        revision: 1,
        text: "first".parse().unwrap(),
        class: None,
        property: None,
        slots: Default::default(),
        proposed_policy: None,
        origin: crate::domain::LeadOrigin::Local,
        source_ref: None,
        endpoint: None,
        flow_ids: Vec::new(),
        producer_confidence: None,
    };
    store.append_lead_revision(&engagement, &lead).unwrap();
    let settled = audit_state(&store);

    for stale in [1, 3] {
        let mut edit = lead.clone();
        edit.revision = stale;
        edit.text = "second".parse().unwrap();
        let error = store.append_lead_revision(&engagement, &edit).unwrap_err();
        assert!(matches!(error, StoreError::RevisionConflict));
        assert_eq!(error.error_code(), ErrorCode::RevisionConflict);
        assert_eq!(error.error_code().exit_code(), 4);
        assert_eq!(audit_state(&store), settled);
    }

    lead.revision = 2;
    lead.text = "second".parse().unwrap();
    let committed = store
        .compare_and_set_lead_revision(&engagement, &lead, Some(1))
        .unwrap();
    assert_eq!(committed, settled.0 + 1);
    lead.revision = 3;
    assert!(matches!(
        store.compare_and_set_lead_revision(&engagement, &lead, Some(1)),
        Err(StoreError::RevisionConflict)
    ));
    let elsewhere: EngagementId = "second".parse().unwrap();
    assert!(matches!(
        store.compare_and_set_lead_revision(&elsewhere, &lead, Some(2)),
        Err(StoreError::RevisionConflict)
    ));
    let stored = (audit_state(&store), store.revision().unwrap());
    assert_eq!(stored, ((committed, settled.1 + 1), committed));
    let texts: Vec<String> = store
        .db
        .prepare("SELECT text FROM lead_revisions WHERE lead_id=? ORDER BY revision")
        .unwrap()
        .query_map([lead.lead_id.as_str()], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(texts, ["first", "second"]);
}

#[test]
fn a_failed_acceptance_leaves_no_run_key_audit_or_revision() {
    let (_dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let run = when(&scope.engagement);
    let settled = audit_state(&store);
    store
        .db
        .execute_batch(
            "CREATE TEMP TRIGGER refuse_key BEFORE INSERT ON request_keys
             BEGIN SELECT RAISE(ABORT, 'test fault'); END;",
        )
        .unwrap();
    assert!(matches!(
        store.declare_metadata_fixture(&scope, &input, &run),
        Err(StoreError::Database(_))
    ));
    assert_eq!(audit_state(&store), settled);
    assert_eq!(row_counts(&store), (0, 0));

    // A second declaration that cannot keep the run identity rolls back too.
    store.db.execute_batch("DROP TRIGGER refuse_key;").unwrap();
    store
        .declare_metadata_fixture(&scope, &input, &run)
        .unwrap();
    let accepted = audit_state(&store);
    let mut copy = run.clone();
    copy.request_key = RequestKey::generate();
    assert!(matches!(
        store.declare_metadata_fixture(&scope, &input, &copy),
        Err(StoreError::Conflict)
    ));
    assert_eq!(audit_state(&store), accepted);
    assert_eq!(row_counts(&store), (1, 1));
}

#[test]
fn a_declaration_never_adopts_or_rewrites_an_existing_run_row() {
    let (_dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let run = when(&scope.engagement);

    // M1.1.2 recorded the run first; the finalize path then settled an outcome
    // that is still unknown, which is exactly what must never be erased.
    let mut finalized = run.clone();
    finalized.state = RunState::Finalized;
    finalized.flags.push(RunFlag::ReconciliationRequired);
    finalized.oracle_result = Some(OracleResult::True);
    finalized.effects = Effect::Unknown;
    finalized.cleanup = Cleanup::Failed;
    store.seed_historical_run_fixture(&finalized).unwrap();
    let durable = run_row(&store, &run.id);
    let settled = audit_state(&store);
    assert!(matches!(
        store.reopen_request(&scope, &run.request_key, &input),
        Err(StoreError::RequestNotFound)
    ));

    // A declaration for that run identity is refused, and nothing about the
    // stored row, its outcome or the audit log changes.
    let error = store
        .declare_metadata_fixture(&scope, &input, &run)
        .unwrap_err();
    assert!(matches!(error, StoreError::Conflict), "{error:?}");
    assert_eq!(error.error_code(), ErrorCode::ConflictingRun);
    assert_eq!(error.error_code().exit_code(), 4);
    assert_eq!(run_row(&store, &run.id), durable);
    assert_eq!(durable.2, "unknown");
    assert_eq!(durable.5, "failed");
    assert_eq!(audit_state(&store), settled);
    assert_eq!(row_counts(&store), (1, 0));
    assert!(
        store
            .find_request(&scope, &run.request_key)
            .unwrap()
            .is_none()
    );

    // The same refusal applies to a run that was only ever declared.
    let mut fresh = when(&scope.engagement);
    fresh.request_key = RequestKey::generate();
    store.seed_historical_run_fixture(&fresh).unwrap();
    assert!(matches!(
        store.declare_metadata_fixture(&scope, &input, &fresh),
        Err(StoreError::Conflict)
    ));
    assert_eq!(row_counts(&store), (2, 0));
}

#[test]
fn a_migrated_legacy_run_is_never_adopted_by_a_declaration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v2.sqlite3");
    let mut db = Connection::open(&path).unwrap();
    let tx = db.transaction().unwrap();
    tx.execute_batch(include_str!("001_initial.sql")).unwrap();
    tx.execute_batch(include_str!("002_audit_receipts.sql"))
        .unwrap();
    tx.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    tx.pragma_update(None, "user_version", 2).unwrap();

    // Two runs from the previous schema: one settled and one only declared.
    let engagement: EngagementId = "local".parse().unwrap();
    let mut legacy = when(&engagement);
    legacy.id = "R-legacy".parse().unwrap();
    legacy.request_key = "rk_legacy".parse().unwrap();
    let mut pending = when(&engagement);
    pending.id = "R-pending".parse().unwrap();
    pending.request_key = "rk_pending".parse().unwrap();
    let digest = legacy.experiment_digest.clone();
    tx.execute("INSERT INTO engagements (id) VALUES ('local')", [])
        .unwrap();
    tx.execute(
        "INSERT INTO runs (id, engagement_id, request_key, experiment_digest, state, flags,
             effects, oracle_result, reproduction, cleanup)
         VALUES (?1, 'local', ?2, ?3, 'finalized', '[\"reconciliation_required\"]', 'unknown',
             'true', 'not_attempted', 'failed')",
        params![
            legacy.id.as_str(),
            legacy.request_key.as_str(),
            digest.as_str()
        ],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO runs (id, engagement_id, request_key, experiment_digest, state, flags,
             effects, oracle_result, reproduction, cleanup)
         VALUES (?1, 'local', ?2, ?3, 'declared', '[]', 'none', NULL, 'not_attempted', 'not_required')",
        params![pending.id.as_str(), pending.request_key.as_str(), digest.as_str()],
    )
    .unwrap();
    assert_eq!(commit(tx, "schema.migrate", "2").unwrap(), 1);
    drop(db);

    let mut store = Store::open(&path).unwrap();
    assert_eq!(
        pragma(&store.db, "user_version").unwrap() as usize,
        MIGRATIONS.len()
    );
    let migrated = audit_state(&store);
    assert_eq!(migrated, (2, 2), "one earlier migrate and one upgrade");
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let durable = run_row(&store, &legacy.id);
    let before = audit_state(&store);

    // The legacy rows carry a request key but no key row: there is nothing to
    // reopen, and nothing may be minted over them either.
    assert!(matches!(
        store.reopen_request(&scope, &legacy.request_key, &input),
        Err(StoreError::RequestNotFound)
    ));
    for run in [&legacy, &pending] {
        let error = store
            .declare_metadata_fixture(&scope, &input, run)
            .unwrap_err();
        assert!(matches!(error, StoreError::Conflict), "{error:?}");
        assert_eq!(error.error_code(), ErrorCode::ConflictingRun);
    }
    assert_eq!(run_row(&store, &legacy.id), durable);
    assert_eq!(audit_state(&store), before);
    assert_eq!(row_counts(&store).1, 0, "no key row was minted");
    assert_eq!(
        store
            .db
            .query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

/// One accepted request in a fresh store, plus a second run of the same
/// engagement that no key names.
struct Accepted {
    dir: TempDir,
    store: Store,
    scope: RequestScope,
    input: NormalizedInput,
    run: Run,
    receipt: u64,
    other: Run,
}

fn accepted() -> Accepted {
    let (dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let run = when(&scope.engagement);
    let receipt = store
        .declare_metadata_fixture(&scope, &input, &run)
        .unwrap()
        .receipt;
    let mut other = when(&scope.engagement);
    other.experiment_digest = Sha256Digest::of(b"other experiment");
    store.seed_historical_run_fixture(&other).unwrap();
    Accepted {
        dir,
        store,
        scope,
        input,
        run,
        receipt,
        other,
    }
}

impl Accepted {
    /// Apply a raw write to the coordination file, as a same-account writer
    /// with access to the database could.
    fn tamper(&self, change: impl FnOnce(&Connection, &RequestKey)) {
        change(&raw(&self.dir), &self.run.request_key);
    }

    /// A replay, a lookup and a resubmission of the tampered key all report one
    /// integrity failure and write nothing. They never report absence or reuse,
    /// so a tampered row cannot be mistaken for a miss or for other input.
    fn assert_integrity(&mut self, case: &str) {
        let settled = audit_state(&self.store);
        let rows = row_counts(&self.store);
        let reopened = self
            .store
            .reopen_request(&self.scope, &self.run.request_key, &self.input);
        let found = self
            .store
            .find_request(&self.scope, &self.run.request_key)
            .map(|found| found.expect("a tampered row is not absent"));
        let redeclared = self
            .store
            .declare_metadata_fixture(&self.scope, &self.input, &self.run);
        for (path, result) in [
            ("reopen", reopened),
            ("find", found),
            ("declare", redeclared),
        ] {
            let error = result.expect_err(case);
            assert!(
                matches!(error, StoreError::Integrity),
                "{case} via {path}: {error:?}"
            );
            assert_eq!(error.error_code(), ErrorCode::IntegrityFailure);
            assert_eq!(error.error_code().exit_code(), 6);
        }
        assert_eq!(audit_state(&self.store), settled, "{case}");
        assert_eq!(row_counts(&self.store), rows, "{case}");
    }
}

#[test]
fn a_tampered_stored_request_row_is_an_integrity_failure() {
    let canonical = String::from_utf8(accepted().input.to_bytes().unwrap()).unwrap();

    // Control: an untampered acceptance replays.
    let mut control = accepted();
    assert_eq!(
        control
            .store
            .reopen_request(&control.scope, &control.run.request_key, &control.input)
            .unwrap()
            .run
            .id,
        control.run.id
    );

    // 1. Semantically equal bytes in another member order, digest untouched.
    let mut case = accepted();
    let reordered = format!(
        r#"{{"command":"verify","schema":"scourge.request-input.v1","arguments":{}}}"#,
        r#"{"lead_revision":null,"engagement_revision":1,"lead_id":"L-1","rounds":2}"#
    );
    assert_ne!(reordered, canonical);
    case.tamper(|db, key| {
        db.execute(
            "UPDATE request_keys SET input=? WHERE key=?",
            params![reordered, key.as_str()],
        )
        .unwrap();
    });
    case.assert_integrity("non-canonical stored bytes");

    // 2. The digest no longer covers the stored bytes.
    let mut case = accepted();
    let other_digest = Sha256Digest::of(b"unrelated bytes").as_str().to_owned();
    case.tamper(|db, key| {
        db.execute(
            "UPDATE request_keys SET input_digest=? WHERE key=?",
            params![other_digest, key.as_str()],
        )
        .unwrap();
    });
    case.assert_integrity("digest mismatch");

    // 3. The key names a different run of the same engagement.
    let mut case = accepted();
    let other_run = case.other.id.clone();
    case.tamper(|db, key| {
        db.execute(
            "UPDATE request_keys SET run_id=? WHERE key=?",
            params![other_run.as_str(), key.as_str()],
        )
        .unwrap();
    });
    case.assert_integrity("key-to-run binding");

    // 4. The run names a different key.
    let mut case = accepted();
    let run_id = case.run.id.clone();
    case.tamper(|db, _| {
        db.execute(
            "UPDATE runs SET request_key='rk_elsewhere' WHERE id=?",
            [run_id.as_str()],
        )
        .unwrap();
    });
    case.assert_integrity("run-to-key binding");

    // 5. The command column disagrees with the stored bytes.
    let mut case = accepted();
    case.tamper(|db, key| {
        db.execute(
            "UPDATE request_keys SET command='retest' WHERE key=?",
            [key.as_str()],
        )
        .unwrap();
    });
    case.assert_integrity("command column");

    // 6. The receipt is not the audit event that accepted this run.
    let mut case = accepted();
    let receipt = integer(case.receipt).unwrap() + 1;
    case.tamper(|db, key| {
        db.execute(
            "UPDATE request_keys SET receipt_revision=? WHERE key=?",
            params![receipt, key.as_str()],
        )
        .unwrap();
    });
    case.assert_integrity("receipt revision");

    // 7. The selector snapshot is not a snapshot an acceptance could write.
    let mut case = accepted();
    case.tamper(|db, key| {
        db.execute(
            "UPDATE request_keys SET lead_revision=NULL WHERE key=?",
            [key.as_str()],
        )
        .unwrap();
    });
    case.assert_integrity("selector snapshot");
}

#[test]
fn one_run_holds_at_most_one_request_key() {
    let accepted = accepted();
    let store = &accepted.store;
    let index_rows: i64 = store
        .db
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='index' AND name='request_key_runs'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(index_rows, 1, "the uniqueness index is part of the schema");
    assert_eq!(row_counts(store), (2, 1));

    // A second key naming an accepted run is refused by the store itself, not
    // only by the read-time binding check.
    let duplicate = store.db.execute(
        "INSERT INTO request_keys (key, engagement_id, binding, command, input, input_digest,
             run_id, receipt_revision, lead_revision, engagement_revision)
         VALUES ('rk_duplicate', 'local', 'workspace:local', 'verify', ?, ?, ?, ?, NULL, 1)",
        params![
            String::from_utf8(accepted.input.to_bytes().unwrap()).unwrap(),
            accepted.input.digest().unwrap().as_str(),
            accepted.run.id.as_str(),
            integer(accepted.receipt).unwrap()
        ],
    );
    assert!(duplicate.is_err(), "a run holds exactly one key");
    assert_eq!(row_counts(store).1, 1);
}

#[test]
fn explicit_revisions_must_exist_in_the_selected_engagement() {
    let (_dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let settled = audit_state(&store);

    // An engagement revision that was never written is not attested.
    let absent = normalized(
        "verify",
        json!({ "lead_id": lead.as_str(), "engagement_revision": 987_654u64 }),
    );
    let error = store
        .declare_metadata_fixture(&scope, &absent, &when(&scope.engagement))
        .unwrap_err();
    assert!(matches!(error, StoreError::SelectorNotFound), "{error:?}");
    assert_eq!(error.error_code(), ErrorCode::ObjectNotFound);
    assert_eq!(error.error_code().exit_code(), 3);
    assert_eq!(audit_state(&store), settled);
    assert_eq!(row_counts(&store), (0, 0));

    // A lead revision that was never written is not attested either.
    let absent = normalized(
        "verify",
        json!({ "lead_id": lead.as_str(), "lead_revision": 3 }),
    );
    assert!(matches!(
        store.declare_metadata_fixture(&scope, &absent, &when(&scope.engagement)),
        Err(StoreError::SelectorNotFound)
    ));
    assert_eq!(audit_state(&store), settled);

    // The revisions that do exist are accepted and snapshotted exactly.
    let present = normalized(
        "verify",
        json!({ "lead_id": lead.as_str(), "lead_revision": 1, "engagement_revision": 1 }),
    );
    let acceptance = store
        .declare_metadata_fixture(&scope, &present, &when(&scope.engagement))
        .unwrap();
    assert_eq!(acceptance.lead_revision, Some(1));
    assert_eq!(acceptance.engagement_revision, 1);
    assert_eq!(acceptance.lead_id, Some(lead));
}

#[test]
fn a_foreign_selector_is_indistinguishable_from_an_absent_one() {
    let (_dir, mut store) = open();
    let own = scope("local", "workspace:local");
    let foreign = scope("second", "workspace:local");
    seed(&mut store, &own.engagement);
    // Another engagement owns a lead with four revisions.
    let foreign_lead = seed(&mut store, &foreign.engagement);
    edit_lead(&mut store, &foreign.engagement, &foreign_lead, 4);
    let settled = audit_state(&store);

    let by_foreign_lead = normalized("verify", json!({ "lead_id": foreign_lead.as_str() }));
    let by_absent_lead = normalized("verify", json!({ "lead_id": LeadId::generate().as_str() }));
    let by_foreign_finding = normalized("retest", json!({ "finding_id": foreign_lead.as_str() }));
    let mut messages = Vec::new();
    for input in [by_foreign_lead, by_absent_lead, by_foreign_finding] {
        let error = store
            .declare_metadata_fixture(&own, &input, &when(&own.engagement))
            .unwrap_err();
        // The same answer as an absent object: no existence, no revision, no
        // lead ID and no engagement is revealed by the refusal.
        assert!(matches!(error, StoreError::SelectorNotFound), "{error:?}");
        assert_eq!(error.error_code(), ErrorCode::ObjectNotFound);
        messages.push(error.to_string());
    }
    assert_eq!(messages[0], messages[1]);
    assert_eq!(messages[0], messages[2]);
    assert_eq!(audit_state(&store), settled);
    assert_eq!(row_counts(&store), (0, 0));

    // The same lead resolves inside its own engagement, so the refusal is a
    // scope decision and not a missing object.
    let owned = normalized("verify", json!({ "lead_id": foreign_lead.as_str() }));
    let acceptance = store
        .declare_metadata_fixture(&foreign, &owned, &when(&foreign.engagement))
        .unwrap();
    assert_eq!(acceptance.lead_revision, Some(4));
}

#[test]
fn concurrent_identical_acceptance_is_one_original_receipt() {
    for _ in 0..30 {
        let (dir, mut store) = open();
        let path = dir.path().join("state.sqlite3");
        let owner = scope("local", "workspace:local");
        let lead = seed(&mut store, &owner.engagement);
        let input = verify_input(lead.as_str());
        let run = when(&owner.engagement);
        drop(store);

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let input = input.clone();
                let run = run.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut store = Store::open(&path).unwrap();
                    let owner = scope("local", "workspace:local");
                    barrier.wait();
                    store.declare_metadata_fixture(&owner, &input, &run)
                })
            })
            .collect();
        let acceptances: Vec<RunAcceptance> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().expect("no caller is refused"))
            .collect();

        // Both callers get the one original acceptance: one run, one key, one
        // receipt and one audit event, with no extra revision.
        assert_eq!(acceptances[0], acceptances[1]);
        assert_eq!(acceptances[0].run.id, run.id);
        let store = Store::open(&path).unwrap();
        assert_eq!(row_counts(&store), (1, 1));
        assert_eq!(accept_events(&store), 1);
        assert_eq!(store.revision().unwrap(), acceptances[0].receipt);
        assert_eq!(acceptances[0].receipt, acceptances[1].receipt);
    }
}

#[test]
fn concurrent_mismatched_acceptance_is_reuse_not_absence() {
    for _ in 0..20 {
        let (dir, mut store) = open();
        let path = dir.path().join("state.sqlite3");
        let owner = scope("local", "workspace:local");
        let lead = seed(&mut store, &owner.engagement);
        let first = verify_input(lead.as_str());
        let second = normalized("verify", json!({ "lead_id": lead.as_str(), "rounds": 4 }));
        drop(store);

        let barrier = Arc::new(Barrier::new(2));
        let same_run = when(&owner.engagement);
        let handles: Vec<_> = [first.clone(), second]
            .into_iter()
            .enumerate()
            .map(|(index, input)| {
                let path = path.clone();
                let run = same_run.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut store = Store::open(&path).unwrap();
                    let owner = scope("local", "workspace:local");
                    barrier.wait();
                    (index, store.declare_metadata_fixture(&owner, &input, &run))
                })
            })
            .collect();
        let mut accepted = 0;
        let mut reused = 0;
        for handle in handles {
            let (_index, result) = handle.join().unwrap();
            match result {
                Ok(_) => accepted += 1,
                Err(error) => {
                    assert!(
                        matches!(error, StoreError::IdempotencyKeyReused),
                        "{error:?}"
                    );
                    assert_eq!(error.error_code(), ErrorCode::IdempotencyKeyReused);
                    reused += 1;
                }
            }
        }
        assert_eq!((accepted, reused), (1, 1));
        let store = Store::open(&path).unwrap();
        assert_eq!(row_counts(&store), (1, 1));
        assert_eq!(accept_events(&store), 1);
    }
}

#[test]
fn a_held_write_lock_is_a_typed_conflict_and_replays_stay_readable() {
    let (dir, mut store) = open();
    let path = dir.path().join("state.sqlite3");
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let run = when(&scope.engagement);
    let acceptance = store
        .declare_metadata_fixture(&scope, &input, &run)
        .unwrap();

    // Another connection holds the only write lock.
    let holder = Connection::open(&path).unwrap();
    holder
        .execute_batch("BEGIN IMMEDIATE; UPDATE store_revision SET revision=revision;")
        .unwrap();

    // Reads on the read snapshot still answer, so a replay of a lost response
    // is never blocked by an unrelated writer.
    assert_eq!(
        store
            .reopen_request(&scope, &run.request_key, &input)
            .unwrap(),
        acceptance
    );
    assert_eq!(
        store.find_request(&scope, &run.request_key).unwrap(),
        Some(acceptance.clone())
    );

    // A mint waits only for the short busy timeout, then reports a retryable
    // local conflict, not an integrity failure.
    let started = Instant::now();
    let error = store
        .declare_metadata_fixture(&scope, &input, &when(&scope.engagement))
        .unwrap_err();
    let waited = started.elapsed();
    assert!(matches!(error, StoreError::Busy), "{error:?}");
    assert_eq!(error.error_code(), ErrorCode::ConflictingRun);
    assert_eq!(error.error_code().exit_code(), 4);
    assert!(waited >= Duration::from_millis(250), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");

    holder.execute_batch("COMMIT;").unwrap();
    assert!(
        store
            .declare_metadata_fixture(&scope, &input, &when(&scope.engagement))
            .is_ok()
    );
}

#[test]
fn a_run_names_each_step_once() {
    let (_dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let mut run = when(&scope.engagement);
    let digest = run.experiment_digest.clone();
    for floor in [Some(1), Some(2)] {
        run.steps.push(RunStep {
            number: 1,
            step: "probe".parse().unwrap(),
            request_digest: digest.clone(),
            flow_id_floor: floor,
            instrument_reference: None,
            effects: None,
            flows: vec![],
        });
    }
    let settled = audit_state(&store);

    // Neither the mint path nor the recording path may collapse a repeated
    // step number into the last one.
    assert!(matches!(
        store.declare_metadata_fixture(&scope, &input, &run),
        Err(StoreError::Conflict)
    ));
    assert_eq!(audit_state(&store), settled);
    assert_eq!(row_counts(&store), (0, 0));
    assert!(matches!(
        store.record_run(&run, None),
        Err(StoreError::Conflict)
    ));
    assert_eq!(audit_state(&store), settled);
    assert_eq!(row_counts(&store), (0, 0));

    // Legacy run imports preserve valid steps in order. Keyed declarations
    // accept only a declared run with no bundled steps.
    run.steps[1].number = 2;
    assert!(matches!(
        store.declare_metadata_fixture(&scope, &input, &run),
        Err(StoreError::Conflict)
    ));
    store.seed_historical_run_fixture(&run).unwrap();
    let recovered = store.recover_run(&run.id).unwrap();
    assert_eq!(recovered.steps.len(), 2);
    assert_eq!(recovered.steps[1].number, 2);
}

#[test]
fn a_lookup_never_mixes_a_key_row_with_another_snapshot() {
    // A writer settles the run while lookups run. Every lookup reports the run
    // the key names with the receipt that accepted it, never a state read from
    // a different snapshot or another run's identity.
    let (dir, mut store) = open();
    let path = dir.path().join("state.sqlite3");
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let run = when(&scope.engagement);
    let acceptance = store
        .declare_metadata_fixture(&scope, &input, &run)
        .unwrap();
    let key = run.request_key.clone();
    let run_id = run.id.clone();
    let reader = Store::open(&path).unwrap();

    let writer_handle = thread::spawn(move || {
        let mut previous = acceptance.receipt;
        let mut update = acceptance.run;
        update.state = RunState::Finalized;
        update.flags.push(RunFlag::FailedBeforeStart);
        for _ in 0..20u64 {
            previous = store
                .record_run(&update, Some(previous))
                .expect("the writer owns the run receipt");
        }
    });
    for _ in 0..200 {
        if let Some(found) = reader.find_request(&scope, &key).unwrap() {
            assert_eq!(found.run.id, run_id);
            assert_eq!(found.run.request_key, key);
            assert_eq!(found.receipt, acceptance.receipt);
        }
    }
    writer_handle.join().unwrap();
}

pub(super) fn seed_recoverable_verification(
    store: &mut Store,
    scope: &RequestScope,
) -> (LeadId, ManifestRevision, Artifact) {
    let manifest = verification_manifest(50);
    let artifact = append_verification_manifest(store, &scope.engagement, &manifest);
    let lead = LeadId::generate();
    store
        .append_lead_revision(
            &scope.engagement,
            &verification_lead_revision(&lead, 1, "first", &manifest),
        )
        .unwrap();
    (lead, manifest, artifact)
}

#[test]
fn read_store_recovery_keeps_intents_and_effects_bound_to_their_runs() {
    let (dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let (lead, manifest, artifact) = seed_recoverable_verification(&mut store, &scope);
    let input = verify_input(lead.as_str());
    let claim = verification_claim(&lead, &manifest);
    let reader = ReadStore::open(&dir.path().join("state.sqlite3")).unwrap();
    let intent = RunStep {
        number: 1,
        step: "probe".parse().unwrap(),
        request_digest: Sha256Digest::of(b"identical request"),
        flow_id_floor: Some(30),
        instrument_reference: None,
        effects: None,
        flows: vec![],
    };

    // Two established sends share the digest. The orphaned intent has no
    // instrument reference and cannot be assigned either flow by digest.
    for flow_id in [31, 32] {
        let mut run = verification_run(&scope.engagement, &claim, &manifest);
        let accepted = admit_verification(
            &mut store, &scope, &input, &run, &claim, &manifest, &artifact,
        )
        .unwrap();
        store
            .claim_conflicts(&run.id, &BTreeSet::from([format!("resource:{flow_id}")]))
            .unwrap();
        store.record_step(&run.id, &intent).unwrap();
        let mut observed = intent.clone();
        observed.effects = Some(Effect::Observed);
        observed.instrument_reference = Some(format!("flow:{flow_id}").parse().unwrap());
        observed.flows.push(Flow {
            step: intent.step.clone(),
            flow_id: Some(flow_id),
            original: None,
            completeness: Completeness::Complete,
            decoder: None,
        });
        store.record_step(&run.id, &observed).unwrap();
        let interim = reader
            .recover(&scope, RecoverySelector::Run(&run.id))
            .unwrap();
        assert_eq!(interim.acceptance.run.effects, Effect::None);
        assert_eq!(
            interim.acceptance.run.steps,
            std::slice::from_ref(&observed)
        );
        run.effects = Effect::Observed;
        run.state = RunState::Finalized;
        run.steps.push(observed);
        store.record_run(&run, Some(accepted.receipt)).unwrap();
        let established = reader
            .recover(&scope, RecoverySelector::RequestKey(&run.request_key))
            .unwrap();
        assert_eq!(established.acceptance.run, run);
        assert!(!established.has_unresolved_dispatch());
    }

    let mut orphaned = verification_run(&scope.engagement, &claim, &manifest);
    let accepted = admit_verification(
        &mut store, &scope, &input, &orphaned, &claim, &manifest, &artifact,
    )
    .unwrap();
    let claim = store
        .claim_conflicts(
            &orphaned.id,
            &BTreeSet::from(["resource:orphaned".to_owned()]),
        )
        .unwrap();
    let intent_revision = store.record_step(&orphaned.id, &intent).unwrap();
    let before_read = (audit_state(&store), row_counts(&store));
    let missing = reader
        .recover(&scope, RecoverySelector::Run(&orphaned.id))
        .unwrap();
    assert_eq!(missing.acceptance.run.effects, Effect::None);
    assert_eq!(missing.acceptance.run.steps, std::slice::from_ref(&intent));
    assert!(missing.has_unresolved_dispatch());
    assert_eq!(missing.run_revision, accepted.receipt);
    assert_eq!(missing.store_revision, intent_revision);
    assert_eq!(
        missing
            .audit
            .iter()
            .map(|event| (event.revision, event.operation.as_str()))
            .collect::<Vec<_>>(),
        [
            (accepted.receipt, "request.accept"),
            (claim, "run.conflicts"),
            (intent_revision, "run.step")
        ]
    );
    assert_eq!((audit_state(&store), row_counts(&store)), before_read);

    let mut unobserved = intent;
    unobserved.effects = Some(Effect::Unknown);
    store.record_step(&orphaned.id, &unobserved).unwrap();
    orphaned.effects = Effect::Unknown;
    orphaned.state = RunState::Finalized;
    orphaned.steps.push(unobserved);
    let finalized = store.record_run(&orphaned, Some(accepted.receipt)).unwrap();
    let before_read = (audit_state(&store), row_counts(&store));
    let unresolved = reader
        .recover(&scope, RecoverySelector::RequestKey(&orphaned.request_key))
        .unwrap();
    assert_eq!(unresolved.acceptance.run, orphaned);
    assert_eq!(unresolved.run_revision, finalized);
    assert!(unresolved.has_unresolved_dispatch());
    assert!(store.conflicts_held(&orphaned.id).unwrap());
    assert_eq!((audit_state(&store), row_counts(&store)), before_read);
}

#[test]
fn read_store_recovery_reopens_exact_request_after_a_durable_refusal() {
    let (dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let (lead, manifest_revision, manifest_artifact) =
        seed_recoverable_verification(&mut store, &scope);
    let input = verify_input(lead.as_str());
    let claim = verification_claim(&lead, &manifest_revision);
    let mut run = verification_run(&scope.engagement, &claim, &manifest_revision);
    let accepted = admit_verification(
        &mut store,
        &scope,
        &input,
        &run,
        &claim,
        &manifest_revision,
        &manifest_artifact,
    )
    .unwrap();
    let asset = Artifact {
        artifact_id: "art_recovery_experiment".parse().unwrap(),
        digest: run.experiment_digest.clone(),
    };
    let claim = store
        .claim_conflicts(&run.id, &BTreeSet::from(["resource:refused".to_owned()]))
        .unwrap();
    let linked = store.link_experiment(&run.id, &asset).unwrap();
    let mut step = RunStep {
        number: 1,
        step: "probe".parse().unwrap(),
        request_digest: Sha256Digest::of(b"refused request"),
        flow_id_floor: Some(30),
        instrument_reference: None,
        effects: None,
        flows: Vec::new(),
    };
    let intent = store.record_step(&run.id, &step).unwrap();
    step.effects = Some(Effect::None);
    let outcome = store.record_step(&run.id, &step).unwrap();
    run.steps.push(step);
    run.state = RunState::Finalized;
    run.flags.push(RunFlag::Refused);
    run.flags.push(RunFlag::FailedBeforeStart);
    let refusal = store.record_run(&run, Some(accepted.receipt)).unwrap();
    edit_lead(&mut store, &scope.engagement, &lead, 2);
    let manifest = manifest();
    let amended = store
        .append_manifest(&scope.engagement, &manifest, &manifest.digest)
        .unwrap();
    let before_read = (audit_state(&store), row_counts(&store));

    let reader = ReadStore::open(&dir.path().join("state.sqlite3")).unwrap();
    let recovered = reader
        .recover(&scope, RecoverySelector::Run(&run.id))
        .unwrap();
    assert_eq!(
        recovered,
        reader
            .recover(&scope, RecoverySelector::RequestKey(&run.request_key))
            .unwrap()
    );
    assert_eq!(recovered.acceptance.run, run);
    assert_eq!(recovered.acceptance.run.effects, Effect::None);
    assert_eq!(
        recovered.acceptance.run.steps[0].effects,
        Some(Effect::None)
    );
    assert!(recovered.acceptance.run.steps[0].flows.is_empty());
    assert!(!recovered.has_unresolved_dispatch());
    assert_eq!(recovered.experiment_artifact_id, Some(asset.artifact_id));
    assert_eq!(recovered.run_revision, refusal);
    assert_eq!(recovered.store_revision, amended);
    assert_eq!(
        recovered
            .audit
            .iter()
            .map(|event| event.revision)
            .collect::<Vec<_>>(),
        [accepted.receipt, claim, linked, intent, outcome, refusal]
    );
    assert_eq!(
        recovered.input.to_bytes().unwrap(),
        input.to_bytes().unwrap()
    );
    assert_eq!(recovered.acceptance.lead_id.as_ref(), Some(&lead));
    assert_eq!(recovered.acceptance.lead_revision, Some(1));
    assert_eq!(recovered.acceptance.engagement_revision, 1);

    let replay = normalized(" verify ", json!({"rounds": 2, "lead_id": lead}));
    assert_eq!(
        store
            .reopen_request(&scope, &run.request_key, &replay)
            .unwrap(),
        recovered.acceptance
    );
    let changed = normalized("verify", json!({"lead_id": lead, "lead_revision": 2}));
    assert!(matches!(
        store.reopen_request(&scope, &run.request_key, &changed),
        Err(StoreError::IdempotencyKeyReused)
    ));
    assert_eq!((audit_state(&store), row_counts(&store)), before_read);
}

#[test]
fn read_store_recovery_keeps_one_snapshot_during_a_writer_commit() {
    let (dir, mut store) = open();
    let scope = scope("local", "workspace:local");
    let lead = seed(&mut store, &scope.engagement);
    let input = verify_input(lead.as_str());
    let mut run = when(&scope.engagement);
    let accepted = store
        .declare_metadata_fixture(&scope, &input, &run)
        .unwrap();
    let reader = ReadStore::open(&dir.path().join("state.sqlite3")).unwrap();

    let committed = reader
        .snapshot(|snapshot| {
            let before = snapshot.recover(&scope, RecoverySelector::Run(&run.id))?;
            run.state = RunState::Finalized;
            run.flags.push(RunFlag::FailedBeforeStart);
            let revision = store.record_run(&run, Some(accepted.receipt))?;
            assert_eq!(
                snapshot.recover(&scope, RecoverySelector::RequestKey(&run.request_key))?,
                before
            );
            assert_eq!(before.acceptance, accepted);
            Ok(revision)
        })
        .unwrap();
    let after = reader
        .recover(&scope, RecoverySelector::Run(&run.id))
        .unwrap();
    assert_eq!(after.acceptance.run, run);
    assert_eq!(after.acceptance.receipt, accepted.receipt);
    assert_eq!(after.store_revision, committed);
    assert_eq!(after.audit.last().unwrap().revision, committed);
}

#[test]
fn read_store_recovery_masks_foreign_and_unbound_selectors() {
    let (dir, mut store) = open();
    let local = scope("local", "workspace:local");
    let other_engagement = scope("foreign", "workspace:local");
    let other_binding = scope("local", "workspace:foreign");
    let lead = seed(&mut store, &local.engagement);
    seed(&mut store, &other_engagement.engagement);
    let input = verify_input(lead.as_str());
    let run = when(&local.engagement);
    store
        .declare_metadata_fixture(&local, &input, &run)
        .unwrap();
    let legacy = when(&local.engagement);
    store.seed_historical_run_fixture(&legacy).unwrap();
    let reader = ReadStore::open(&dir.path().join("state.sqlite3")).unwrap();

    // A corrupt foreign request remains absent; recovery must filter the
    // selected scope before decoding an acceptance's normalized input.
    raw(&dir)
        .execute(
            "UPDATE request_keys SET input_digest='corrupt' WHERE key=?",
            [run.request_key.as_str()],
        )
        .unwrap();
    for foreign in [&other_engagement, &other_binding] {
        for selector in [
            RecoverySelector::Run(&run.id),
            RecoverySelector::RequestKey(&run.request_key),
        ] {
            assert!(matches!(
                reader.recover(foreign, selector),
                Err(StoreError::SelectorNotFound)
            ));
            assert!(matches!(
                reader.recover(&local, selector),
                Err(StoreError::Integrity)
            ));
        }
    }
    let absent = when(&local.engagement);
    for run in [&legacy, &absent] {
        for selector in [
            RecoverySelector::Run(&run.id),
            RecoverySelector::RequestKey(&run.request_key),
        ] {
            assert!(matches!(
                reader.recover(&local, selector),
                Err(StoreError::SelectorNotFound)
            ));
        }
    }
    reader
        .snapshot(|snapshot| {
            assert!(
                snapshot
                    .scope(local.engagement.clone())?
                    .run(&legacy.id)
                    .is_ok()
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn read_store_recovery_masks_ambiguous_legacy_request_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v3.sqlite3");
    let mut db = Connection::open(&path).unwrap();
    let tx = db.transaction().unwrap();
    for migration in &MIGRATIONS[..3] {
        tx.execute_batch(migration).unwrap();
    }
    tx.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    tx.pragma_update(None, "user_version", 3).unwrap();
    let scope = scope("local", "workspace:local");
    let run = when(&scope.engagement);
    tx.execute(
        "INSERT INTO engagements (id) VALUES (?)",
        [scope.engagement.as_str()],
    )
    .unwrap();
    create_run(&tx, &run).unwrap();
    let receipt = advance(&tx, "request.accept", run.id.as_str()).unwrap();
    let input = normalized("self-test", json!({}));
    let input_bytes = String::from_utf8(input.to_bytes().unwrap()).unwrap();
    tx.execute(
        "INSERT INTO request_keys VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, 0)",
        params![
            run.request_key.as_str(),
            scope.engagement.as_str(),
            scope.binding.as_str(),
            input.command(),
            input_bytes,
            input.digest().unwrap().as_str(),
            run.id.as_str(),
            integer(receipt).unwrap(),
        ],
    )
    .unwrap();
    tx.commit().unwrap();

    let reader = ReadStore::open(&path).unwrap();
    let recovered = reader
        .recover(&scope, RecoverySelector::Run(&run.id))
        .unwrap();
    assert_eq!(recovered.acceptance.run, run);
    assert_eq!(recovered.experiment_artifact_id, None);
    assert_eq!(recovered.input, input);
    let other = RequestKey::generate();
    db.execute(
        "INSERT INTO request_keys
         SELECT ?1, engagement_id, binding, command, input, input_digest,
                run_id, receipt_revision, lead_id, lead_revision, engagement_revision
         FROM request_keys WHERE key=?2",
        (other.as_str(), run.request_key.as_str()),
    )
    .unwrap();
    for selector in [
        RecoverySelector::Run(&run.id),
        RecoverySelector::RequestKey(&run.request_key),
        RecoverySelector::RequestKey(&other),
    ] {
        assert!(matches!(
            reader.recover(&scope, selector),
            Err(StoreError::SelectorNotFound)
        ));
    }
    let foreign = RequestScope::new(
        scope.engagement.clone(),
        "workspace:foreign".parse().unwrap(),
    );
    db.execute(
        "UPDATE request_keys SET binding=?1 WHERE key=?2",
        (foreign.binding.as_str(), other.as_str()),
    )
    .unwrap();
    for (scope, key) in [(&scope, &run.request_key), (&foreign, &other)] {
        for selector in [
            RecoverySelector::Run(&run.id),
            RecoverySelector::RequestKey(key),
        ] {
            assert!(matches!(
                reader.recover(scope, selector),
                Err(StoreError::SelectorNotFound)
            ));
        }
    }
}
