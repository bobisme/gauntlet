//! Generated offline histories against the §5.1 status contract. Each seed
//! varies record timestamps, custody and the placement of invalid runs around
//! fixed witnesses. Expectations name records by their independently assigned
//! IDs. On failure we trim the unobserved suffix and remove irrelevant runs
//! while preserving the failed assertion and its witness.

use super::*;
use crate::status::{
    Applicability::{self, AsObserved, FixedWithinTestedScope, StillViolated, Unestablished},
    Audience::{self, Internal, ThirdParty},
    Computed, LastOutcome, LeadState, RegistrySnapshot,
    Status::{self, Conditional, IntegrityFailure, NeedsReview, Refuted, Verified},
    StatusComputer, StatusSnapshot,
};
use scourge_core::{
    engagement::{EngagementDraft, ManifestRevision, PassPin},
    store::read::ReadStore,
    wire::{FunctionalResult, PropertyResult, Retest, RetestMode},
};

const SEEDS: [u64; 4] = [0x5354_0001, 0x5354_0002, 0x5354_0003, 0x5354_0004];

#[derive(Clone, Copy, Debug)]
enum Rule {
    Absent,
    OwnerOnly,
    Authenticated,
}

#[derive(Clone, Copy, Debug)]
enum RunKind {
    Positive,
    Negative,
    Invalid,
    Unlinked,
    Unsupported,
    ConflictingVerdict,
    ConflictingMemo,
    Retest {
        baseline: &'static str,
        property: PropertyResult,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reader {
    Public,
    ValidatedRetests,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Expectation {
    name: &'static str,
    audience: Audience,
    reader: Reader,
    result: Computed,
}

#[derive(Clone, Debug)]
enum Action {
    Publish {
        name: &'static str,
        kind: RunKind,
        custody: Custody,
        deployment: u8,
    },
    ChangeRule(Rule),
    EditText,
    LoseOriginal(&'static str),
    Check(Expectation),
}

#[derive(Clone, Debug)]
struct Step {
    action: Action,
    second: usize,
    generated_noise: bool,
}

#[derive(Clone, Debug)]
struct Case {
    seed: u64,
    name: &'static str,
    initial_rule: Rule,
    steps: Vec<Step>,
}

fn publish(name: &'static str, kind: RunKind) -> Action {
    captured(name, kind, Custody::Isolated, 0)
}

fn captured(name: &'static str, kind: RunKind, custody: Custody, deployment: u8) -> Action {
    Action::Publish {
        name,
        kind,
        custody,
        deployment,
    }
}

fn record_id(name: &str) -> VerificationId {
    format!("V-status-{name}").parse().unwrap()
}

fn check(
    name: &'static str,
    status: Status,
    applicability: Applicability,
    ids: Option<(&str, &str)>,
) -> Action {
    Action::Check(Expectation {
        name,
        audience: Internal,
        reader: Reader::Public,
        result: Computed {
            status,
            applicability,
            status_record: ids.map(|(s, _)| record_id(s)),
            deciding_record: ids.map(|(_, d)| record_id(d)),
            qualified: true,
        },
    })
}

fn for_reader(action: Action, audience: Audience, reader: Reader) -> Action {
    let Action::Check(mut check) = action else {
        unreachable!("only a check has an audience")
    };
    check.audience = audience;
    check.reader = reader;
    Action::Check(check)
}

fn retest(baseline: &'static str, property: PropertyResult) -> RunKind {
    RunKind::Retest { baseline, property }
}

fn witnesses() -> impl IntoIterator<Item = (&'static str, Rule, Vec<Action>)> {
    use PropertyResult::{NoViolationWithinTestedScope, StillViolated as Violation};
    use Rule::*;
    use RunKind::*;

    let internal = |action| for_reader(action, Internal, Reader::ValidatedRetests);
    let third_party = |action| for_reader(action, ThirdParty, Reader::ValidatedRetests);
    let lead = |last| Status::Lead {
        state: LeadState::Open,
        last,
    };
    [
        (
            "chain sequence and text edits",
            OwnerOnly,
            vec![
                publish("old", Positive),
                publish("new", Positive),
                check(
                    "newer by sequence",
                    Verified,
                    AsObserved,
                    Some(("new", "new")),
                ),
                publish("invalid-after-true", Invalid),
                check(
                    "invalid after S",
                    Verified,
                    AsObserved,
                    Some(("new", "new")),
                ),
                publish("negative", Negative),
                check(
                    "matching negative",
                    Verified,
                    Unestablished,
                    Some(("new", "negative")),
                ),
                publish("invalid", Invalid),
                check(
                    "invalid after D",
                    Verified,
                    Unestablished,
                    Some(("new", "negative")),
                ),
                Action::EditText,
                check(
                    "only text edited",
                    Verified,
                    Unestablished,
                    Some(("new", "negative")),
                ),
            ],
        ),
        (
            "conflicting stored verdict",
            OwnerOnly,
            vec![
                publish("old", Positive),
                check(
                    "original re-evaluates",
                    Verified,
                    AsObserved,
                    Some(("old", "old")),
                ),
                publish("conflict", ConflictingVerdict),
                check(
                    "verdict contradicts originals",
                    IntegrityFailure,
                    Unestablished,
                    Some(("conflict", "conflict")),
                ),
            ],
        ),
        (
            "conflicting stored memo",
            OwnerOnly,
            vec![
                publish("old", Positive),
                check(
                    "before conflicting memo",
                    Verified,
                    AsObserved,
                    Some(("old", "old")),
                ),
                publish("conflict", ConflictingMemo),
                check(
                    "memo contradicts originals",
                    IntegrityFailure,
                    Unestablished,
                    Some(("conflict", "conflict")),
                ),
            ],
        ),
        (
            "missing original for S",
            OwnerOnly,
            vec![
                publish("positive", Positive),
                publish("negative", Negative),
                check(
                    "S and D available",
                    Verified,
                    Unestablished,
                    Some(("positive", "negative")),
                ),
                Action::LoseOriginal("positive"),
                check(
                    "S lost an original",
                    IntegrityFailure,
                    Unestablished,
                    Some(("positive", "negative")),
                ),
            ],
        ),
        (
            "missing original for D",
            OwnerOnly,
            vec![
                publish("positive", Positive),
                publish("fix", retest("positive", NoViolationWithinTestedScope)),
                internal(check(
                    "validated retest",
                    Verified,
                    FixedWithinTestedScope,
                    Some(("positive", "fix")),
                )),
                check(
                    "M1 retest oracle unavailable",
                    Verified,
                    Unestablished,
                    Some(("positive", "fix")),
                ),
                Action::LoseOriginal("fix"),
                check(
                    "D lost an original",
                    IntegrityFailure,
                    Unestablished,
                    Some(("positive", "fix")),
                ),
            ],
        ),
        (
            "mixed custody and newer true",
            OwnerOnly,
            vec![
                publish("isolated", Positive),
                captured("shared", Positive, Custody::Shared, 0),
                captured(
                    "fix",
                    retest("shared", NoViolationWithinTestedScope),
                    Custody::Shared,
                    0,
                ),
                internal(check(
                    "F-50 internal",
                    Verified,
                    FixedWithinTestedScope,
                    Some(("shared", "fix")),
                )),
                third_party(check(
                    "F-50 third party",
                    Verified,
                    Unestablished,
                    Some(("isolated", "isolated")),
                )),
                publish("new", Positive),
                internal(check(
                    "true supersedes fix",
                    Verified,
                    AsObserved,
                    Some(("new", "new")),
                )),
                third_party(check(
                    "true supersedes weaker records",
                    Verified,
                    AsObserved,
                    Some(("new", "new")),
                )),
            ],
        ),
        (
            "deployment after D",
            OwnerOnly,
            vec![
                publish("positive", Positive),
                publish("retest", retest("positive", Violation)),
                publish("invalid", Invalid),
                internal(check(
                    "same deployment",
                    Verified,
                    StillViolated,
                    Some(("positive", "retest")),
                )),
                captured("new-deployment", Invalid, Custody::Shared, 1),
                internal(check(
                    "changed deployment",
                    Verified,
                    Unestablished,
                    Some(("positive", "retest")),
                )),
            ],
        ),
        (
            "policy admission and replacement",
            Absent,
            vec![
                publish("old", Positive),
                check(
                    "no rule at run",
                    Conditional,
                    AsObserved,
                    Some(("old", "old")),
                ),
                Action::ChangeRule(OwnerOnly),
                check(
                    "first rule admitted",
                    Verified,
                    AsObserved,
                    Some(("old", "old")),
                ),
                publish("under-denial", Positive),
                Action::ChangeRule(Authenticated),
                check(
                    "replacement leaves historical finding",
                    Verified,
                    Unestablished,
                    Some(("under-denial", "under-denial")),
                ),
                publish("under-allowance", Positive),
                check(
                    "new run judged under replacement",
                    Refuted,
                    AsObserved,
                    Some(("under-allowance", "under-allowance")),
                ),
            ],
        ),
        (
            "nonpromoting artifacts",
            OwnerOnly,
            vec![
                publish("unlinked", Unlinked),
                check(
                    "unlinked true is invisible",
                    lead(LastOutcome::None),
                    Unestablished,
                    None,
                ),
                publish("invalid", Invalid),
                check(
                    "linked invalid is a lead",
                    lead(LastOutcome::Invalid),
                    Unestablished,
                    None,
                ),
                publish("unsupported", Unsupported),
                check(
                    "unsupported oracle cannot verify",
                    NeedsReview,
                    Unestablished,
                    Some(("unsupported", "unsupported")),
                ),
                publish("genuine", Positive),
                captured("unlinked-later", Unlinked, Custody::Shared, 1),
                check(
                    "unlinked true cannot replace S",
                    Verified,
                    AsObserved,
                    Some(("genuine", "genuine")),
                ),
            ],
        ),
    ]
}

// A small fixed generator keeps ordinary CI offline and makes case replay
// independent of the clock, test scheduling and randomized IDs from the store.
fn generate(seed: u64, name: &'static str, initial_rule: Rule, witness: Vec<Action>) -> Case {
    let mut state = seed;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (state >> 32) as usize
    };
    let mut steps = Vec::new();
    let mut deployment = 0;
    let mut has_run = false;
    for (index, mut action) in witness.into_iter().enumerate() {
        if let Action::Publish {
            kind,
            custody,
            deployment: marker,
            ..
        } = &mut action
        {
            if !matches!(name, "mixed custody and newer true") && next().is_multiple_of(2) {
                *custody = Custody::Shared;
            }
            if !matches!(kind, RunKind::Unlinked) {
                deployment = *marker;
                has_run = true;
            }
        }
        steps.push(Step {
            action,
            second: 0,
            generated_noise: false,
        });
        if has_run && next().is_multiple_of(3) {
            const NOISE: [&str; 11] = [
                "noise-0", "noise-1", "noise-2", "noise-3", "noise-4", "noise-5", "noise-6",
                "noise-7", "noise-8", "noise-9", "noise-10",
            ];
            steps.push(Step {
                action: captured(NOISE[index], RunKind::Invalid, Custody::Shared, deployment),
                second: 0,
                generated_noise: true,
            });
        }
    }
    let offset = next() % 5;
    for (position, step) in steps.iter_mut().enumerate() {
        step.second = offset
            + if seed.is_multiple_of(2) {
                position
            } else {
                50 - position
            };
    }
    Case {
        seed,
        name,
        initial_rule,
        steps,
    }
}

fn manifest(rule: Rule, parent: Option<&ManifestRevision>) -> ManifestRevision {
    let source = include_str!("../../../../../fixtures/target/schema-examples/engagement.toml");
    let replacement = match rule {
        Rule::Absent => "",
        Rule::OwnerOnly => "readers = \"owner\"\n",
        Rule::Authenticated => "readers = \"authenticated\"\n",
    };
    let draft = EngagementDraft::parse_toml(
        source
            .replacen("readers = \"owner\"\n", replacement, 1)
            .as_bytes(),
    )
    .unwrap();
    let reference = "pass.development-fixture".parse().unwrap();
    let digest = Sha256Digest::of(b"fixture pass");
    let pass = PassPin {
        reference: &reference,
        digest: &digest,
    };
    match parent {
        Some(parent) => parent.amend(draft, pass).unwrap(),
        None => draft.accept(pass).unwrap(),
    }
}

struct History {
    _directory: tempfile::TempDir,
    store: Store,
    read: ReadStore,
    evidence: FakeEvidence,
    engagement: EngagementId,
    lead: LeadRevision,
    manifest: ManifestRevision,
    records: Vec<(Artifact, VerificationV1)>,
}

impl History {
    fn new(rule: Rule) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.sqlite3");
        let mut history = Self {
            _directory: directory,
            store: Store::open(&path).unwrap(),
            read: ReadStore::open(&path).unwrap(),
            evidence: FakeEvidence::default(),
            engagement: "record-test".parse().unwrap(),
            lead: LeadRevision {
                lead_id: context().lead_id,
                revision: 1,
                text: "initial lead text".parse().unwrap(),
                class: Some("web-authz/private-object-read".parse().unwrap()),
                property: Some("orders".parse().unwrap()),
                slots: BTreeMap::new(),
                proposed_policy: None,
                origin: LeadOrigin::Local,
                source_ref: None,
                endpoint: None,
                flow_ids: Vec::new(),
                producer_confidence: None,
            },
            manifest: manifest(rule, None),
            records: Vec::new(),
        };
        history.append_manifest();
        history
            .store
            .append_lead_revision(&history.engagement, &history.lead)
            .unwrap();
        history
    }

    fn append_manifest(&mut self) {
        let artifact = self.evidence.insert(
            &format!("manifest_{}", self.manifest.revision()),
            self.manifest.canonical_bytes().to_vec(),
        );
        self.store
            .append_manifest(&self.engagement, &artifact, self.manifest.pass_digest())
            .unwrap();
    }

    fn publish(
        &mut self,
        name: &str,
        kind: RunKind,
        custody: Custody,
        deployment: u8,
        second: usize,
    ) {
        let case = match kind {
            RunKind::Negative | RunKind::ConflictingVerdict => F2Case::False,
            RunKind::Invalid => F2Case::Partial,
            RunKind::Retest {
                property: PropertyResult::NoViolationWithinTestedScope,
                ..
            } => F2Case::False,
            _ => F2Case::True,
        };
        let mut fixture = fixture(case);
        fixture.run = format!("R-status-{name}").parse().unwrap();
        fixture.experiment.engagement.revision = self.manifest.revision();
        fixture.experiment.engagement.digest = self.manifest.digest().clone();
        let property = fixture.experiment.property.as_mut().unwrap();
        let declared = self.manifest.properties().get(&property.label).unwrap();
        property.digest = Sha256Digest::of(&scourge_core::canonical::to_vec(declared).unwrap());
        let (experiment_bytes, experiment_digest) = fixture.experiment.freeze().unwrap();
        fixture.experiment_digest = experiment_digest;
        fixture.experiment_artifact = self
            .evidence
            .insert(&format!("{name}_experiment"), experiment_bytes);
        // Each run needs a separate receipt for every original, even where
        // its saved bytes match another run's. S and D can lose evidence independently.
        let remap = |original: &mut Artifact| {
            let bytes = fixture.evidence.read(original).unwrap().bytes;
            *original = self
                .evidence
                .insert(&format!("{name}_{}", original.artifact_id.as_str()), bytes);
        };
        for original in &mut fixture.retained {
            remap(original);
        }
        for round in &mut fixture.rounds {
            for original in round
                .flows
                .iter_mut()
                .filter_map(|f| f.reference.original.as_mut())
            {
                remap(original);
            }
            for original in round
                .cleanup
                .iter_mut()
                .flat_map(|c| &mut c.flows)
                .filter_map(|f| f.original.as_mut())
            {
                remap(original);
            }
        }

        let (_, head) = self.store.checkpoint(&self.engagement).unwrap();
        let mut context = context();
        context.sequence = head.sequence + 1;
        context.prev_record_digest = head.record_digest.clone();
        context.lead_revision = self.lead.revision;
        context.custody = custody;
        context.target.deployment_marker =
            Some(format!("deployment-{deployment}").parse().unwrap());
        context.started_at = timestamp(&format!("2026-11-24T00:00:{second:02}Z"));
        context.finished_at = timestamp(&format!("2026-11-24T00:00:{:02}Z", second + 1));
        let mut prepared =
            evaluate_and_prepare_with(&self.evidence, fixture.acquisition(), context).unwrap();
        let record = &mut prepared.record;
        record.record_id = record_id(name);
        let nonce = Sha256Digest::of(name.as_bytes());
        record.run_nonce = nonce.as_str()[..32].parse().unwrap();
        match kind {
            RunKind::Unsupported => record.oracle.version = "999".parse().unwrap(),
            RunKind::ConflictingVerdict => {
                record.result = OracleResult::True;
                record.exposure = Some(Exposure::CrossPrincipal);
                record.reproduction = Reproduction::Reproduced;
                record.rounds[0].result = OracleResult::True;
                record.rounds[0].exposure = record.exposure;
            }
            RunKind::ConflictingMemo => {
                record.rounds[0].after_owner_read = !record.rounds[0].after_owner_read;
            }
            RunKind::Retest { baseline, property } => {
                let (artifact, baseline) = self.record(baseline);
                assert_eq!(record.oracle, baseline.oracle);
                assert_eq!(record.experiment_digest, baseline.experiment_digest);
                record.kind = RecordKind::Retest;
                record.retest = Some(Retest {
                    baseline_record: baseline.record_id.clone(),
                    baseline_digest: artifact.digest.clone(),
                    mode: RetestMode::Sequential,
                    property_result: property,
                    functional_result: FunctionalResult::PreservedWithinTestedScope,
                    paired_baseline_target: None,
                    intermittent_sampling: None,
                });
            }
            _ => {}
        }
        prepared.bytes = wire::to_vec(record).unwrap();
        let intent = PublicationIntentV1 {
            schema: PublicationIntentV1Tag::PublicationIntentV1,
            intent_id: format!("P-status-{name}").parse().unwrap(),
            engagement: self.engagement.clone(),
            run_id: fixture.run.clone(),
            record_id: record.record_id.clone(),
            record_digest: Sha256Digest::of(&prepared.bytes),
            expected_head: head,
            state: PublicationState::Pending,
            artifact_id: None,
        };
        if matches!(kind, RunKind::Unlinked) {
            // Store a fully re-evaluated artifact with a plausible sequence,
            // predecessor and deployment, but with no coordination intent.
            store_prepared(&self.evidence, intent.intent_id.as_str(), prepared).unwrap();
            return;
        }
        add_fixture_run(&mut self.store, &fixture, record.result);
        self.store
            .stage_publication(&intent, &prepared.bytes, &prepared.inputs)
            .unwrap();
        let key = intent.intent_id.as_str();
        let (artifact, record) = match kind {
            RunKind::Positive | RunKind::Negative | RunKind::Invalid => {
                let stored = store_prepared(&self.evidence, key, prepared).unwrap();
                (stored.artifact, stored.record)
            }
            // These frozen test records deliberately reach the read boundary
            // through an exact linkage without a production verifier writer.
            _ => (
                self.evidence
                    .store(key, &prepared.bytes, &prepared.inputs)
                    .unwrap(),
                prepared.record,
            ),
        };
        let bytes = wire::to_vec(&record).unwrap();
        self.store
            .complete_publication(&intent.intent_id, &artifact, &bytes)
            .unwrap();
        self.records.push((artifact, record));
    }

    fn record(&self, name: &str) -> &(Artifact, VerificationV1) {
        self.records
            .iter()
            .find(|(_, r)| r.record_id == record_id(name))
            .unwrap()
    }

    fn apply(&mut self, step: &Step) {
        match step.action {
            Action::Publish {
                name,
                kind,
                custody,
                deployment,
            } => {
                self.publish(name, kind, custody, deployment, step.second);
            }
            Action::ChangeRule(rule) => {
                self.manifest = manifest(rule, Some(&self.manifest));
                self.append_manifest();
            }
            Action::EditText => {
                self.lead.revision += 1;
                self.lead.text = "edited lead prose with identical bindings".parse().unwrap();
                self.store
                    .append_lead_revision(&self.engagement, &self.lead)
                    .unwrap();
            }
            Action::LoseOriginal(name) => {
                let original = self.record(name).1.rounds[0].flows[0]
                    .original
                    .as_ref()
                    .unwrap();
                assert!(
                    self.evidence
                        .bytes
                        .lock()
                        .unwrap()
                        .remove(original.artifact_id.as_str())
                        .is_some()
                );
            }
            Action::Check(_) => unreachable!("checks do not modify history"),
        }
    }

    fn compute(&self, check: &Expectation) -> Computed {
        let lead = &self.lead.lead_id;
        let chain = self
            .read
            .snapshot(|read| read.scope(self.engagement.clone())?.linked_chain(lead))
            .unwrap();
        let snapshot = capture_linked_with(&self.evidence, &chain, lead).unwrap();
        // Both audience projections start from the same records, including
        // both custody tiers. Unlinked artifacts never reach this boundary.
        assert_eq!(snapshot.records(), self.records.as_slice());
        let registry = RegistrySnapshot::compiled();
        match check.reader {
            Reader::Public => StatusComputer::compute(
                lead,
                &StatusSnapshot::from_capture(Ok(snapshot)).unwrap(),
                check.audience,
                &registry,
            ),
            Reader::ValidatedRetests => StatusComputer::compute_for_test(
                lead,
                &snapshot,
                check.audience,
                &registry,
                false,
                false,
                |artifact, record| match snapshot.reevaluate(artifact) {
                    Ok(_) => Some(true),
                    Err(RecordError::OracleUnavailable) => Some(record.kind == RecordKind::Retest),
                    Err(_) => None,
                },
            ),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Failure {
    expectation: Expectation,
    actual: Computed,
}

fn replay(case: &Case) -> Result<usize, Box<Failure>> {
    let mut history = History::new(case.initial_rule);
    let mut checked = 0;
    for step in &case.steps {
        if let Action::Check(expectation) = &step.action {
            let actual = history.compute(expectation);
            if actual != expectation.result {
                return Err(Box::new(Failure {
                    expectation: expectation.clone(),
                    actual,
                }));
            }
            checked += 1;
        } else {
            history.apply(step);
        }
    }
    Ok(checked)
}

fn minimize(mut case: Case, failure: &Failure) -> Case {
    let failed_check = case.steps.iter().position(|step| {
        matches!(&step.action, Action::Check(expectation) if expectation == &failure.expectation)
    }).unwrap();
    case.steps.truncate(failed_check + 1);
    loop {
        let reduced = case
            .steps
            .iter()
            .enumerate()
            .filter(|(_, step)| step.generated_noise)
            .find_map(|(index, _)| {
                let mut smaller = case.clone();
                smaller.steps.remove(index);
                (replay(&smaller).err().as_deref() == Some(failure)).then_some(smaller)
            });
        match reduced {
            Some(smaller) => case = smaller,
            None => return case,
        }
    }
}

#[test]
fn generated_status_histories() {
    let mut histories = 0;
    let mut decisions = 0;
    let mut noise = 0;
    for seed in SEEDS {
        for (name, initial_rule, witness) in witnesses() {
            let case = generate(seed, name, initial_rule, witness);
            noise += case
                .steps
                .iter()
                .filter(|step| step.generated_noise)
                .count();
            decisions += replay(&case).unwrap_or_else(|failure| {
                let minimized = minimize(case.clone(), &failure);
                let actual = &failure.actual;
                panic!(
                    "status history {}, seed {:#x}\n{failure:#?}\nObserved S={:?}, D={:?}\nMinimized history:\n{minimized:#?}",
                    case.name, case.seed,
                    actual.status_record.as_ref().map(VerificationId::as_str),
                    actual.deciding_record.as_ref().map(VerificationId::as_str),
                );
            });
            histories += 1;
        }
    }
    assert_eq!(histories, 36);
    assert_eq!(decisions, 112);
    assert!(
        noise >= histories,
        "expected generated invalid records throughout the histories"
    );
    eprintln!(
        "status properties: seeds {SEEDS:x?}, {histories} histories, {decisions} decisions, {noise} generated invalid runs"
    );
}
