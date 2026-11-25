#[cfg(target_os = "linux")]
use std::{fs, path::Path};

#[cfg(target_os = "linux")]
use serde_json::Value;
use serde_json::json;

use crate::{
    domain::LeadOrigin,
    workspace::{
        TrustedPrincipalSlot,
        runtime_authority_tests::{DECLARATION, runtime_for, workspace_for},
    },
};

use super::*;

fn lead() -> LeadRevision {
    LeadRevision {
        lead_id: "L-planning".parse().unwrap(),
        revision: 1,
        text: "read policy preview".parse().unwrap(),
        class: Some("web-authz/private-object-read".parse().unwrap()),
        property: Some("orders".parse().unwrap()),
        slots: BTreeMap::new(),
        proposed_policy: Some(json!({"readers": "owner"})),
        origin: LeadOrigin::Local,
        source_ref: None,
        endpoint: None,
        flow_ids: Vec::new(),
        producer_confidence: None,
    }
}

fn slot(name: &str, value: &str) -> SlotValue {
    SlotValue {
        name: name.parse().unwrap(),
        value: value.parse().unwrap(),
    }
}

fn operator_owner(binding: &mut VerifierRuntimeAuthority) {
    binding.principal_slots.insert(
        "owner".parse().unwrap(),
        TrustedPrincipalSlot {
            principal: "alice".parse().unwrap(),
            provenance: "test operator".parse().unwrap(),
        },
    );
}

fn project(
    workspace: &BoundWorkspace,
    lead: &LeadRevision,
    preview: &[SlotValue],
) -> Result<BoundVerificationPlan, ErrorCode> {
    bound_verification_plan(workspace, &"one".parse().unwrap(), lead, preview, 2)
}

#[test]
fn unsupported_and_fixed_slots_are_refused_before_authority_lookup() {
    let mut workspace = workspace_for(runtime_for(DECLARATION), DECLARATION);
    workspace.authority.verifier_runtime.clear();
    let mut input = lead();
    let property_override = [slot("read", "operation.other.read")];
    input.class = Some("web-authz/collection-disclosure".parse().unwrap());
    assert_eq!(
        project(&workspace, &input, &property_override).unwrap_err(),
        ErrorCode::OracleUnavailable
    );
    input.class = lead().class;
    assert_eq!(
        project(&workspace, &input, &property_override).unwrap_err(),
        ErrorCode::SlotConflict
    );
    input
        .slots
        .insert("read".parse().unwrap(), json!("operation.orders.read"));
    assert_eq!(
        project(&workspace, &input, &[]).unwrap_err(),
        ErrorCode::SlotConflict
    );
}

#[test]
fn operator_slots_survive_incomplete_forms_and_conflict_with_hypotheses() {
    let mut binding = runtime_for(DECLARATION);
    operator_owner(&mut binding);
    let workspace = workspace_for(binding, DECLARATION);
    let mut input = lead();
    let plan = project(&workspace, &input, &[]).unwrap();
    assert_eq!(plan.blockers, [ErrorCode::SlotsIncomplete]);
    assert!(plan.execution.is_none());
    assert_eq!(plan.missing.len(), 1);
    assert_eq!(plan.missing[0].name.as_str(), "other");
    let owner = &plan.slots[&"owner".parse().unwrap()];
    assert_eq!(owner.source, PlannedSlotSource::Engagement);
    assert_eq!(owner.supplied_by.as_str(), "test operator");
    assert_eq!(
        project(&workspace, &input, &[slot("owner", "alice")]).unwrap_err(),
        ErrorCode::InputAmbiguous
    );
    input.slots.insert("owner".parse().unwrap(), json!("bob"));
    assert_eq!(
        project(&workspace, &input, &[]).unwrap_err(),
        ErrorCode::InputAmbiguous
    );
    input.slots.clear();
    input.slots.insert("other".parse().unwrap(), json!("bob"));
    assert_eq!(
        project(&workspace, &input, &[slot("other", "bob")]).unwrap_err(),
        ErrorCode::InputAmbiguous
    );
    assert_eq!(
        project(&workspace, &lead(), &[slot("other", "alice")]).unwrap_err(),
        ErrorCode::InputAmbiguous
    );
}

#[test]
fn only_pinned_policy_and_owner_provenance_can_raise_the_ceiling() {
    let mut input = lead();
    input.slots.insert("owner".parse().unwrap(), json!("alice"));
    input.slots.insert("other".parse().unwrap(), json!("bob"));
    let workspace = workspace_for(runtime_for(DECLARATION), DECLARATION);
    let projected = project(&workspace, &input, &[]).unwrap();
    assert_eq!(
        projected.slots[&"owner".parse().unwrap()].source,
        PlannedSlotSource::Lead
    );
    let execution = projected.execution.unwrap();
    assert_eq!(
        execution.policy_ceiling.highest(),
        PositiveStatus::Conditional
    );
    assert_eq!(execution.native_pass, None);
    assert_eq!(projected.blockers, [ErrorCode::EnforcementUnavailable]);

    let declaration = std::str::from_utf8(DECLARATION).unwrap();
    input.slots.remove(&"owner".parse().unwrap());
    for (text, unauthenticated, cross_principal) in [
        ("", PositiveStatus::Conditional, PositiveStatus::Conditional),
        (
            "readers = \"public\"\n",
            PositiveStatus::Refuted,
            PositiveStatus::Refuted,
        ),
        (
            "readers = \"authenticated\"\n",
            PositiveStatus::Verified,
            PositiveStatus::Refuted,
        ),
        (
            "readers = \"owner\"\n",
            PositiveStatus::Verified,
            PositiveStatus::Verified,
        ),
    ] {
        let declaration = declaration.replacen("readers = \"owner\"\n", text, 1);
        let mut binding = runtime_for(declaration.as_bytes());
        operator_owner(&mut binding);
        let workspace = workspace_for(binding, declaration.as_bytes());
        let plan = project(&workspace, &input, &[]).unwrap();
        assert_eq!(
            plan.execution.unwrap().policy_ceiling,
            PolicyCeiling {
                unauthenticated,
                cross_principal
            }
        );
    }

    input.slots.remove(&"other".parse().unwrap());
    let plan = project(
        &workspace,
        &input,
        &[slot("owner", "alice"), slot("other", "bob")],
    )
    .unwrap();
    assert_eq!(
        plan.slots[&"owner".parse().unwrap()].source,
        PlannedSlotSource::Preview
    );
    assert_eq!(
        plan.execution.unwrap().policy_ceiling.highest(),
        PositiveStatus::Conditional
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bound_plan_reports_native_and_compiled_budgets_from_passive_argv() {
    let root = tempfile::tempdir().unwrap();
    let declaration = std::str::from_utf8(DECLARATION)
        .unwrap()
        .replace(
            "required_custody = \"shared\"",
            "required_custody = \"isolated\"",
        )
        .replace(
            "required_enforcement = \"none\"",
            "required_enforcement = \"egress\"",
        );
    let declaration = declaration.as_bytes();
    let mut binding = runtime_for(declaration);
    operator_owner(&mut binding);
    install_passive_fixture(root.path(), &mut binding);
    let workspace = workspace_for(binding, declaration);
    let projected = project(&workspace, &lead(), &[slot("other", "bob")]).unwrap();
    assert_eq!(projected.required_custody, Custody::Isolated);
    assert_eq!(projected.required_enforcement, RequiredEnforcement::Egress);
    assert_eq!(
        projected.slots[&"other".parse().unwrap()].source,
        PlannedSlotSource::Preview
    );
    let execution = projected.execution.unwrap();
    assert_eq!(execution.custody, Custody::Shared);
    assert_eq!(
        execution.configured_sessions,
        [
            ("owner".parse().unwrap(), ConfiguredSession::Verifier),
            ("other".parse().unwrap(), ConfiguredSession::Verifier),
        ]
        .into()
    );
    let dispatches = &execution.registered.dispatches;
    assert!(
        dispatches
            .iter()
            .any(|item| item.session.as_str() == "alice_verify")
    );
    assert!(
        dispatches
            .iter()
            .any(|item| item.session.as_str() == "bob_verify")
    );
    assert_eq!(execution.target_isolation, None);
    assert_eq!(dispatches.len(), 12);
    assert_eq!(dispatches.iter().map(|item| item.actions).sum::<u64>(), 13);
    assert_eq!(
        dispatches
            .iter()
            .find(|item| item.flow == "C")
            .unwrap()
            .actions,
        2
    );
    let native_pass = execution.native_pass.unwrap();
    assert_eq!(native_pass.enforcement, EnforcementStatus::Unenforced);
    assert_eq!(native_pass.id.as_str(), "scourge-development-fixture");
    assert_eq!(native_pass.requests_spent, Some(1));
    assert_eq!(native_pass.requests_left, Some(7));
    assert_eq!(execution.policy_ceiling.highest(), PositiveStatus::Verified);
    assert_eq!(execution.registered.round_count, 2);
    assert_eq!(
        execution.registered.required_requests,
        execution.registered.requests_per_round * 2
    );
    assert!(execution.registered.required_requests > 8);
    assert_eq!(
        execution.native_budget,
        Some(NativeBudget {
            macro_requests: 1,
            units_left: Some(8),
            macro_within_ceiling: Some(true),
            compiled_requests_fit: Some(false),
        })
    );
    assert_eq!(
        projected.blockers,
        [
            ErrorCode::CapabilityUnavailable,
            ErrorCode::EnforcementUnavailable,
            ErrorCode::BudgetRefused,
        ]
    );
    let log = fs::read_to_string(root.path().join("argv")).unwrap();
    assert_eq!(
        log.lines()
            .filter(|line| *line != "version")
            .collect::<Vec<_>>(),
        [
            "proxy status",
            "pass show",
            "macros run create-order --session alice_verify --dry-run",
            "proxy status",
            "pass show"
        ]
    );

    let pass_path = root.path().join("pass");
    let pass: Value = serde_json::from_slice(&fs::read(&pass_path).unwrap()).unwrap();
    let macro_path = root.path().join("macro");
    let dry_run: Value = serde_json::from_slice(&fs::read(&macro_path).unwrap()).unwrap();
    for (engine_left, pass_spent, pass_left, fit) in [
        (Some(200), Some(1), Some(8), Some(false)),
        (Some(8), Some(1), Some(200), Some(true)),
        (Some(0), Some(1), Some(200), Some(false)),
        (Some(200), None, Some(200), None),
        (Some(200), Some(1), None, None),
        (Some(200), None, None, None),
        (None, Some(1), Some(200), None),
    ] {
        let mut pass = pass.clone();
        pass["pass"]["ceilings"] = if pass_spent.is_none() && pass_left.is_none() {
            json!([])
        } else {
            json!([request_counter(pass_spent, pass_left)])
        };
        fs::write(&pass_path, serde_json::to_vec(&pass).unwrap()).unwrap();
        let mut dry_run = dry_run.clone();
        dry_run["run"]["units_left"] = json!(engine_left);
        fs::write(&macro_path, serde_json::to_vec(&dry_run).unwrap()).unwrap();

        let plan = project(&workspace, &lead(), &[slot("other", "bob")]).unwrap();
        let execution = plan.execution.unwrap();
        let pass = execution.native_pass.unwrap();
        let budget = execution.native_budget.unwrap();
        assert_eq!(
            (pass.requests_spent, pass.requests_left),
            (pass_spent, pass_left)
        );
        assert_eq!(budget.units_left, engine_left);
        assert_eq!(
            budget.macro_within_ceiling,
            engine_left.map(|left| left >= 1)
        );
        assert_eq!(
            budget.compiled_requests_fit, fit,
            "{engine_left:?}/{pass_spent:?}/{pass_left:?}"
        );
        assert_eq!(
            plan.blockers.contains(&ErrorCode::BudgetRefused),
            fit == Some(false)
        );
        assert_eq!(
            plan.blockers.contains(&ErrorCode::AccountingUnestablished),
            fit.is_none()
        );
    }

    fs::write(root.path().join("argv"), "").unwrap();
    for (key, other, code) in [
        (
            "digest",
            "sha256:mismatch",
            ErrorCode::AccountingUnestablished,
        ),
        (
            "id",
            "pass.development-fixture",
            ErrorCode::EnforcementUnavailable,
        ),
    ] {
        let mut changed = pass.clone();
        changed["pass"][key] = json!(other);
        fs::write(&pass_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        let blocked = project(&workspace, &lead(), &[slot("other", "bob")]).unwrap();
        let execution = blocked.execution.unwrap();
        assert!(execution.native_pass.is_none());
        assert!(execution.native_budget.is_none());
        assert!(
            blocked.blockers.contains(&code),
            "{key}: {:?}",
            blocked.blockers
        );
        assert!(
            !fs::read_to_string(root.path().join("argv"))
                .unwrap()
                .contains("macros")
        );
    }
}

#[cfg(target_os = "linux")]
fn install_passive_fixture(root: &Path, binding: &mut VerifierRuntimeAuthority) {
    use std::os::unix::fs::symlink;

    let launcher =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-script-launcher.sh");
    symlink(launcher, root.join("wrapper")).unwrap();
    fs::write(
        root.join(".scourge-test-script"),
        r#"
set -eu
[ "$1" = --project ] && [ "$2" = "$HOME/project" ] && [ "$3" = --json ]
shift 3
printf '%s\n' "$*" >> "$HOME/argv"
case "$*" in
    "version") file=version ;;
    "proxy status") file=proxy ;;
    "pass show") file=pass ;;
    "macros run create-order --session alice_verify --dry-run") file=macro ;;
    *) exit 99 ;;
esac
exec /bin/cat "$HOME/$file"
"#,
    )
    .unwrap();
    binding.teapot.executable = root.join("wrapper");
    binding.teapot.project = root.join("project");
    binding.teapot.home = root.to_owned();
    binding.teapot.wrapper = true;
    binding.pass.path = root.join("planned-pass");
    binding.engine.enforced = false;
    binding.engine.policy_locked = false;

    macro_rules! capture {
        ($name:literal) => {
            serde_json::from_str::<Value>(include_str!(concat!(
                "../../../../fixtures/contracts/",
                $name,
                ".json"
            )))
            .unwrap()["output"]
                .take()
        };
    }
    let pass_id = "scourge-development-fixture";
    let pass_path = &binding.pass.path;
    let digest = format!("sha256:{}", binding.pass.digest.as_str());
    let mut version = capture!("describe");
    let engine = &mut version["version"]["engine"];
    engine["project"] = json!(binding.teapot.project);
    engine["instance"] = json!(binding.engine.instance);
    engine["project_id"] = json!(binding.engine.project_id);
    engine["pass"] = json!(pass_path);
    let mut proxy = capture!("describe-status");
    proxy["proxy"]["engine"] = engine.clone();
    proxy["proxy"]["project"] = json!(binding.teapot.project);
    let health = &mut proxy["proxy"]["health"];
    health["policy_lock"]["pass_path"] = json!(pass_path);
    health["policy_lock"]["pass"] = json!({"id": pass_id, "digest": digest});
    health["gate"]["state"] = json!("bound");
    health["gate"]["pass"] = json!({
        "id": pass_id, "path": pass_path, "digest": digest, "current_digest": digest, "window": "valid",
    });
    let mut pass = capture!("units-left");
    pass["pass"]["pass_file"] = json!(pass_path);
    pass["pass"]["digest"] = json!(digest);
    pass["pass"]["state"] = json!("bound");
    pass["pass"]["id"] = json!(pass_id);
    pass["pass"]["window"] = json!("valid");
    pass["pass"]["enforcement"]["code"] = json!("not-enforced");
    pass["pass"]["ceilings"] = json!([request_counter(Some(1), Some(7))]);

    let mut dry_run = capture!("dry-run");
    dry_run["run"]["name"] = json!("create-order");
    dry_run["run"]["session"]["name"] = json!("alice_verify");
    dry_run["run"]["units"] = json!(1);
    dry_run["run"]["units_left"] = json!(8);
    dry_run["run"]["steps"].as_array_mut().unwrap().truncate(1);
    dry_run["run"]["state_changing"] = json!([]);
    for (name, value) in [
        ("version", version),
        ("proxy", proxy),
        ("pass", pass),
        ("macro", dry_run),
    ] {
        fs::write(root.join(name), serde_json::to_vec(&value).unwrap()).unwrap();
    }
}

#[cfg(target_os = "linux")]
fn request_counter(spent: Option<u64>, left: Option<u64>) -> Value {
    json!({"counter": "requests", "total": 256, "spent": spent, "left": left, "unused": 0})
}
