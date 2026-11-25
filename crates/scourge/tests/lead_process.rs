use std::{
    fs,
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixListener,
    path::PathBuf,
    process::{Command, Output},
};

use scourge_core::{
    domain::{LeadEventKind, LeadOrigin, LeadRevision},
    ids::{EngagementId, LeadId},
    wire::ResponseV1,
    workspace::{self, Authority, TeapotProjectAuthority},
};
use serde_json::Value;
use tempfile::TempDir;

const ENGAGEMENT: &[u8] =
    include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");
const HOSTILE: &str = "HOSTILE_RESPONSE_BODY_DO_NOT_COPY_73c1";

struct World {
    temporary: TempDir,
    workspace: PathBuf,
    state: PathBuf,
    log: PathBuf,
    target: PathBuf,
    wrapper: Option<PathBuf>,
}

impl World {
    fn local() -> Self {
        Self::new(false)
    }

    fn teapot() -> Self {
        Self::new(true)
    }

    fn new(with_teapot: bool) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("workspace");
        let state = temporary.path().join("state");
        let project = temporary.path().join("teapot-project");
        let home = temporary.path().join("home");
        let log = temporary.path().join("process.log");
        let target = temporary.path().join("target.sock");
        for path in [&workspace, &state, &project, &home] {
            fs::create_dir_all(path).unwrap();
        }
        let wrapper = with_teapot.then(|| {
            let path = temporary.path().join("teapot-wrapper");
            let source = format!(r#"#!/bin/bash
set -eu
if [[ -n "${{SC_SECRET+x}}" ]]; then exit 88; fi
printf '%s\n' "$*" >> '{}'
if [[ "${{1:-}}" == "positive-control" ]]; then
  printf x | nc -q 0 -U '{}'
  exit $?
fi
if [[ "${{4:-}}" == "findings" && "${{5:-}}" == "show" && "${{6:-}}" == "7" ]]; then
  printf '%s\n' '{{"finding":{{"id":7,"check":"authz.idor","confidence":"certain","title":"Private order exposure","description":"{HOSTILE}","remediation":"{HOSTILE}","detail":{{"body":"{HOSTILE}"}},"endpoint":{{"scheme":"https","host":"api.example.test","port":443,"method":"GET","path":"/orders/17","shape":"s1"}},"reproduction":{{"flow":13,"note":"{HOSTILE}"}},"evidence":[{{"flow":12,"note":"{HOSTILE}"}},{{"flow":13,"note":"{HOSTILE}"}}]}}}}'
  exit 0
fi
if [[ "${{4:-}}" == "leads" && "${{5:-}}" == "show" ]]; then
  printf '%s\n' '{{"lead":{{"id":5,"rule":"lead.object-id","title":"Object-shaped route","endpoint":{{"host":"api.example.test","port":443,"method":"GET","path":"/orders/17","shape":"s1"}},"flows":[12],"detail":{{"body":"{HOSTILE}"}}}}}}'
  exit 0
fi
if [[ "${{4:-}}" == "flows" && "${{5:-}}" == "list" ]]; then
  if [[ "${{6:-}}" == "session:session.alice" ]]; then
    if [[ "$*" == *"--after 1000"* ]]; then
      printf '%s\n' '{{"flows":[{{"id":1012,"method":"GET","host":"api.example.test","path":"/orders/17","scheme":"https","port":443}}]}}'
    else
      printf '{{"flows":['
      for ((id=1; id<=1000; id++)); do
        if ((id > 1)); then printf ','; fi
        printf '{{"id":%s,"method":"GET","host":"api.example.test","path":"/older","scheme":"https","port":443}}' "$id"
      done
      printf '%s\n' '],"advice":[{{"level":"info","type":"next-page","message":"after 1000","command":"teapot flows list session:session.alice --after 1000"}}]}}'
    fi
  else
    printf '%s\n' '{{"flows":[]}}'
  fi
  exit 0
fi
exit 77
"#, log.display(), target.display());
            fs::write(&path, source).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        });
        let authority = wrapper
            .as_ref()
            .map_or_else(Authority::default, |wrapper| Authority {
                teapot_projects: [(
                    "project.teapot.development".to_owned(),
                    TeapotProjectAuthority {
                        executable: wrapper.clone(),
                        project,
                        home,
                        config_home: None,
                        data_home: None,
                        state_home: None,
                        cache_home: None,
                        runtime_dir: None,
                        wrapper: true,
                    },
                )]
                .into(),
                ..Authority::default()
            });
        workspace::init(&workspace, &state, "demo", ENGAGEMENT, authority).unwrap();
        Self {
            temporary,
            workspace,
            state,
            log,
            target,
            wrapper,
        }
    }

    fn run(&self, args: &[&str], format: &str) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_scourge"));
        command
            .current_dir(self.temporary.path())
            .env("XDG_STATE_HOME", &self.state)
            .env("SC_SECRET", "credential-positive-control")
            .env_remove("FORMAT")
            .args(["--format", format, "--workspace"])
            .arg(&self.workspace)
            .args(["--engagement", "demo"])
            .args(args)
            .output()
            .unwrap()
    }

    fn json(&self, args: &[&str]) -> (Output, ResponseV1, Value) {
        let output = self.run(args, "json");
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: ResponseV1 = scourge_core::wire::from_slice(&output.stdout).unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        (output, response, value)
    }

    fn detail(&self, id: &LeadId) -> scourge_core::store::read::LeadDetail {
        let bound = workspace::select(&self.workspace, Some(&self.workspace), &self.state).unwrap();
        bound
            .open_coordination()
            .unwrap()
            .snapshot(|snapshot| {
                snapshot
                    .scope(EngagementId::from_str("demo").unwrap())?
                    .lead_detail(id)
            })
            .unwrap()
    }

    fn seed_lead(&self, lead: LeadRevision) -> u64 {
        let bound = workspace::select(&self.workspace, Some(&self.workspace), &self.state).unwrap();
        let mut store = bound.open_coordination_writer().unwrap();
        let engagement: EngagementId = "demo".parse().unwrap();
        store.append_lead_revision(&engagement, &lead).unwrap();
        store.revision().unwrap()
    }
}

use std::str::FromStr;

#[test]
fn text_only_is_one_call_and_its_complete_scoped_next_argv_executes() {
    let world = World::local();
    let (output, response, value) = world.json(&["lead", "add", "Possible private order"]);
    assert!(output.status.success(), "{value:#}");
    assert_eq!(response.result.as_ref().unwrap().as_str(), "lead-added");
    let lead: LeadId = value["lead"]["id"].as_str().unwrap().parse().unwrap();
    let argv = response.next[0]
        .argv
        .iter()
        .map(|word| word.as_str())
        .collect::<Vec<_>>();
    assert_eq!(argv[0..3], ["scourge", "--format", "json"]);
    assert!(
        argv.windows(2)
            .any(|pair| pair == ["--workspace", world.workspace.to_str().unwrap()])
    );
    assert!(argv.windows(2).any(|pair| pair == ["--engagement", "demo"]));
    assert_eq!(&argv[argv.len() - 3..], ["verify", lead.as_str(), "--plan"]);

    let next = Command::new(env!("CARGO_BIN_EXE_scourge"))
        .current_dir(world.temporary.path())
        .env("XDG_STATE_HOME", &world.state)
        .env_remove("FORMAT")
        .args(&argv[1..])
        .output()
        .unwrap();
    assert!(
        next.status.success(),
        "{}{}",
        String::from_utf8_lossy(&next.stdout),
        String::from_utf8_lossy(&next.stderr)
    );
    let planned: Value = serde_json::from_slice(&next.stdout).unwrap();
    assert_eq!(planned["workspace"], world.workspace.to_str().unwrap());
    assert_eq!(planned["engagement"], "demo");
    assert_eq!(planned["experiment"]["target_traffic"], false);

    let text = world.run(&["lead", "add", "Second observation"], "text");
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("lead add  lead-added"), "{text}");
    assert!(text.contains("next  scourge --format json"), "{text}");
}

#[test]
fn verify_refuses_unsupported_class_and_fixed_preview_before_any_adapter_or_receipt() {
    let world = World::teapot();
    let unsupported: LeadId = "L-unsupported".parse().unwrap();
    let revision = world.seed_lead(LeadRevision {
        lead_id: unsupported.clone(),
        revision: 1,
        text: "unsupported collection observation".parse().unwrap(),
        class: Some("web-authz/collection-disclosure".parse().unwrap()),
        property: Some("orders".parse().unwrap()),
        slots: Default::default(),
        proposed_policy: None,
        origin: LeadOrigin::Local,
        source_ref: None,
        endpoint: None,
        flow_ids: Vec::new(),
        producer_confidence: None,
    });
    let (output, response, value) = world.json(&["verify", unsupported.as_str()]);
    assert_eq!(output.status.code(), Some(5), "{value:#}");
    assert_eq!(response.error.unwrap().code.as_str(), "ORACLE_UNAVAILABLE");
    assert_eq!(value["lead_remains_lead"], true);
    assert!(!world.log.exists(), "an adapter was invoked before refusal");

    let supported: LeadId = "L-fixed-preview".parse().unwrap();
    world.seed_lead(LeadRevision {
        lead_id: supported.clone(),
        revision: 1,
        text: "fixed property override".parse().unwrap(),
        class: Some("web-authz/private-object-read".parse().unwrap()),
        property: Some("orders".parse().unwrap()),
        slots: [
            ("owner".parse().unwrap(), serde_json::json!("alice")),
            ("other".parse().unwrap(), serde_json::json!("bob")),
        ]
        .into(),
        proposed_policy: None,
        origin: LeadOrigin::Local,
        source_ref: None,
        endpoint: None,
        flow_ids: Vec::new(),
        producer_confidence: None,
    });
    let (_, response, value) = world.json(&[
        "verify",
        supported.as_str(),
        "--plan",
        "--slot",
        "read=operation.other.read",
    ]);
    assert_eq!(response.error.unwrap().code.as_str(), "SLOT_CONFLICT");
    assert_eq!(value["effects"], "none");
    assert!(!world.log.exists(), "an adapter was invoked before refusal");
    let bound = workspace::select(&world.workspace, Some(&world.workspace), &world.state).unwrap();
    assert_eq!(
        bound
            .open_coordination_writer()
            .unwrap()
            .revision()
            .unwrap(),
        revision + 1,
        "verify refusal wrote an admission receipt"
    );
}

#[test]
fn import_is_idempotent_copies_only_bounded_metadata_and_never_connects() {
    let world = World::teapot();
    let listener = UnixListener::bind(&world.target).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (first, _, first_value) = world.json(&["lead", "add", "--from", "teapot:finding:7"]);
    assert!(first.status.success(), "{first_value:#}");
    let (second, _, second_value) = world.json(&["lead", "add", "--from", "teapot:finding:7"]);
    assert!(second.status.success(), "{second_value:#}");
    assert_eq!(first_value["lead"]["id"], second_value["lead"]["id"]);
    assert_eq!(second_value["result"], "lead-reopened");
    let rendered = format!("{first_value}{second_value}");
    assert!(!rendered.contains(HOSTILE));
    assert!(
        listener.accept().is_err(),
        "passive import connected to the target control"
    );

    let id: LeadId = first_value["lead"]["id"].as_str().unwrap().parse().unwrap();
    let detail = world.detail(&id);
    assert_eq!(detail.lead.text.as_str(), "Private order exposure");
    assert_eq!(
        detail.lead.class.as_ref().unwrap().as_str(),
        "web-authz/private-object-read"
    );
    assert_eq!(detail.lead.flow_ids, [12, 13]);
    assert_eq!(
        detail.lead.producer_confidence.as_ref().unwrap().as_str(),
        "certain"
    );
    assert_eq!(detail.events.len(), 1, "idempotent replay appended history");
    let stored = serde_json::to_string(&detail.lead).unwrap();
    assert!(!stored.contains(HOSTILE));

    let log = fs::read_to_string(&world.log).unwrap();
    assert_eq!(
        log.lines().count(),
        2,
        "the connected process did not run exactly twice"
    );
    assert!(log.lines().all(|line| line.contains("findings show 7")));

    // Harness positive control: the same connected executable reaches the
    // local target witness if an effectful argv is used. The passive adapter
    // above did run the process, inherited no SC_SECRET, and made no socket.
    let wrapper = world.wrapper.as_ref().unwrap();
    listener.set_nonblocking(false).unwrap();
    let mut positive = Command::new(wrapper)
        .arg("positive-control")
        .spawn()
        .unwrap();
    let _ = listener.accept().unwrap();
    assert!(positive.wait().unwrap().success());
}

#[test]
fn fixed_slots_are_refused_before_teapot_and_history_is_attributed() {
    let world = World::teapot();
    let listener = UnixListener::bind(&world.target).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (refused, response, value) = world.json(&[
        "lead",
        "add",
        "x",
        "--flow",
        "12",
        "--class",
        "web-authz/private-object-read",
        "--slot",
        "read=orders",
    ]);
    assert_eq!(refused.status.code(), Some(2), "{value:#}");
    assert_eq!(response.error.unwrap().code.as_str(), "SLOT_CONFLICT");
    assert!(
        !world.log.exists(),
        "Teapot started before fixed-slot refusal"
    );
    assert!(listener.accept().is_err());

    let (_, ambiguous, value) = world.json(&[
        "lead",
        "add",
        "x",
        "--flow",
        "12",
        "--class",
        "web-authz/private-object-read",
        "--slot",
        "owner=alice",
        "--slot",
        "other=alice",
    ]);
    assert_eq!(
        ambiguous.error.unwrap().code.as_str(),
        "INPUT_AMBIGUOUS",
        "{value:#}"
    );
    assert!(
        !world.log.exists(),
        "Teapot started before ambiguous-principal refusal"
    );
    assert!(listener.accept().is_err());

    let (missing, missing_response, missing_value) =
        world.json(&["lead", "add", "Captured private order", "--flow", "1012"]);
    assert_eq!(missing.status.code(), Some(5), "{missing_value:#}");
    assert_eq!(
        missing_response.error.unwrap().code.as_str(),
        "SLOTS_INCOMPLETE"
    );
    assert!(
        listener.accept().is_err(),
        "role refusal sent target traffic"
    );

    let (_, flow_response, flow_value) = world.json(&[
        "lead",
        "add",
        "Captured private order",
        "--flow",
        "1012",
        "--slot",
        "owner=alice",
        "--slot",
        "other=bob",
    ]);
    assert_eq!(flow_value["result"], "lead-added");
    let flow_id: LeadId = flow_value["lead"]["id"].as_str().unwrap().parse().unwrap();
    let flow_detail = world.detail(&flow_id);
    assert_eq!(
        flow_detail.lead.class.as_ref().unwrap().as_str(),
        "web-authz/private-object-read"
    );
    assert_eq!(
        flow_detail.lead.property.as_ref().unwrap().as_str(),
        "orders"
    );
    assert_eq!(flow_detail.lead.slots[&"owner".parse().unwrap()], "alice");
    assert_eq!(flow_detail.lead.slots[&"other".parse().unwrap()], "bob");
    let log = fs::read_to_string(&world.log).unwrap();
    assert!(
        log.lines()
            .any(|line| line.contains("flows list session:session.alice")
                && line.contains("--after 1000")),
        "flow lookup did not page beyond the first 1000 rows: {log}"
    );
    assert!(
        listener.accept().is_err(),
        "flow intake sent target traffic"
    );
    let argv = flow_response.next[0]
        .argv
        .iter()
        .map(|word| word.as_str())
        .collect::<Vec<_>>();
    let planned = Command::new(env!("CARGO_BIN_EXE_scourge"))
        .current_dir(world.temporary.path())
        .env("XDG_STATE_HOME", &world.state)
        .args(&argv[1..])
        .output()
        .unwrap();
    let plan: Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(plan["experiment"]["complete"], true, "{plan:#}");
    assert_eq!(plan["experiment"]["target_traffic"], false);

    let (_, _, created) = world.json(&[
        "lead",
        "add",
        "review",
        "--class",
        "web-authz/private-object-read",
        "--property",
        "orders",
        "--slot",
        "owner=alice",
        "--slot",
        "other=bob",
        "--actor",
        "alice-agent",
    ]);
    let id: LeadId = created["lead"]["id"].as_str().unwrap().parse().unwrap();
    let before_invalid = world.detail(&id);
    for args in [
        vec![
            "lead",
            "set",
            id.as_str(),
            "--text",
            "silently changed",
            "--reason",
            "bad\nreason",
        ],
        vec!["lead", "withdraw", id.as_str(), "--reason", "bad\nreason"],
        vec!["lead", "defer", id.as_str(), "--reason", "bad\nreason"],
        vec![
            "lead",
            "duplicate",
            id.as_str(),
            "--of",
            flow_id.as_str(),
            "--reason",
            "bad\nreason",
        ],
    ] {
        let (output, response, value) = world.json(&args);
        assert_eq!(output.status.code(), Some(2), "{value:#}");
        assert_eq!(response.error.unwrap().code.as_str(), "USAGE_ERROR");
        let after = world.detail(&id);
        assert_eq!(after.lead.revision, before_invalid.lead.revision);
        assert_eq!(after.lead.text, before_invalid.lead.text);
        assert_eq!(after.events, before_invalid.events);
    }
    let (_, _, set) = world.json(&[
        "lead",
        "set",
        id.as_str(),
        "--slot",
        "other=alice",
        "--slot",
        "owner=bob",
        "--actor",
        "reviewer",
    ]);
    assert_eq!(set["result"], "lead-set");
    let (_, _, deferred) = world.json(&["lead", "defer", id.as_str(), "--actor", "triage"]);
    assert_eq!(deferred["result"], "lead-deferred");
    let detail = world.detail(&id);
    assert_eq!(detail.lead.revision, 2);
    assert_eq!(detail.events.len(), 3);
    assert_eq!(detail.events[0].actor.as_str(), "alice-agent");
    assert_eq!(detail.events[1].actor.as_str(), "reviewer");
    assert!(matches!(
        detail.events[1].kind,
        LeadEventKind::Set {
            class_changed: false,
            slots_changed: true
        }
    ));
    assert_eq!(detail.events[2].actor.as_str(), "triage");
    assert!(matches!(detail.events[2].kind, LeadEventKind::Deferred));
}
