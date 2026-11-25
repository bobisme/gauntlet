use std::{cell::Cell, fs, os::unix::fs::symlink, path::Path, process::Command, time::Duration};

use serde_json::json;

use super::*;
use crate::teapot::{BoundEngine, Environment, ExecutableKind, OutputStream, TransportFailure};

const PASS: &str = "pass";
const PROXY: &str = "proxy";
const RULES: &str = "rules";
const INTERCEPT: &str = "intercept";
const INTERCEPT_RULES: &str = "intercept-rules";
const SCRIPTS: &str = "scripts";
const SESSION: &str = "session";
const CONFIG: &str = "config";

struct Fixture {
    root: tempfile::TempDir,
    teapot: Teapot,
    session: [SessionName; 1],
}

impl Fixture {
    fn new(enforced: bool, policy_locked: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path();
        let project = dir.join("fixture project");
        fs::create_dir(&project).unwrap();
        fs::write(
            dir.join(".scourge-test-script"),
            r#"
if [ "$#" -lt 4 ] || [ "$1" != --project ] || [ "$2" != "$HOME/fixture project" ] || [ "$3" != --json ]; then
    printf 'bad argv\n' >> "$HOME/forbidden"
    exit 99
fi
shift 3
case "$*" in
    "version") file=version ;;
    "proxy status") file=proxy ;;
    "pass show") file=pass ;;
    "rules list") file=rules ;;
    "intercept status") file=intercept ;;
    "intercept rules list") file=intercept-rules ;;
    "scripts list") file=scripts ;;
    "sessions show alice") file=session ;;
    "config list") file=config ;;
    *) printf '%s\n' "$*" >> "$HOME/forbidden"; exit 99 ;;
esac
printf '%s\n' "$file" >> "$HOME/observed"
if [ "$file" = rules ] && [ -f "$HOME/slow" ]; then
    exec /bin/sleep 10
fi
if [ "$file" = rules ] && [ -f "$HOME/replace-version" ]; then
    /bin/cp "$HOME/replace-version" "$HOME/version"
fi
if [ "$file" = pass ] && [ -f "$HOME/pass-error" ]; then
    /bin/cat "$HOME/pass-error" >&2
    exit 0
fi
exec /bin/cat "$HOME/$file"
"#,
        )
        .unwrap();
        let launcher =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-script-launcher.sh");
        symlink(launcher, dir.join("wrapper")).unwrap();
        let abs = |path: &Path| path.to_str().unwrap().parse().unwrap();
        let fixture = Self {
            teapot: Teapot::new(
                abs(&dir.join("wrapper")),
                ExecutableKind::Wrapper,
                abs(&project),
                Environment {
                    home: abs(dir),
                    config_home: None,
                    data_home: None,
                    state_home: None,
                    cache_home: None,
                    runtime_dir: None,
                },
                BoundEngine {
                    instance: "bound-instance".parse().unwrap(),
                    project_id: "bound-project".parse().unwrap(),
                    enforced,
                    policy_locked,
                },
            ),
            root,
            session: ["alice".parse().unwrap()],
        };
        fixture.reset();
        // This executable is only a reply fixture. Prove that the guard
        // would witness a send, macro, or session probe in its argv.
        let forbidden = fixture.root.path().join("forbidden");
        let mut expected = String::new();
        for args in [
            ["requests", "send"],
            ["macros", "run"],
            ["sessions", "check"],
        ] {
            let output = Command::new(fixture.teapot.executable.as_str())
                .env_clear()
                .env("HOME", fixture.root.path())
                .args(["--project", fixture.teapot.project.as_str(), "--json"])
                .args(args)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(99));
            expected.push_str(&format!("{}\n", args.join(" ")));
        }
        assert_eq!(fs::read_to_string(&forbidden).unwrap(), expected);
        fs::remove_file(forbidden).unwrap();
        fixture
    }

    fn reset(&self) {
        macro_rules! captured {
            ($file:literal) => {
                serde_json::from_str::<Value>(include_str!(concat!(
                    "../../../../../fixtures/contracts/",
                    $file,
                    ".json"
                )))
                .unwrap()["output"]
                    .take()
            };
        }
        let mut version = captured!("describe");
        let mut proxy = captured!("describe-status");
        let expected = &self.teapot.engine;
        let engine = &mut version["version"]["engine"];
        engine["project"] = json!(self.teapot.project.as_str());
        engine["instance"] = json!(expected.instance.as_str());
        engine["project_id"] = json!(expected.project_id.as_str());
        engine["enforced"] = json!(expected.enforced);
        engine["policy_locked"] = json!(expected.policy_locked);
        proxy["proxy"]["engine"] = engine.clone();
        proxy["proxy"]["project"] = engine["project"].clone();
        proxy["proxy"]["health"]["policy_lock"]["locked"] = json!(expected.policy_locked);
        self.write("version", &version);
        self.write(PROXY, &proxy);
        self.write(PASS, &captured!("units-left"));
        self.write(RULES, &captured!("edit-rules"));
        self.write(INTERCEPT, &captured!("edit-intercept"));
        self.write(INTERCEPT_RULES, &captured!("edit-intercept-rules"));
        self.write(SCRIPTS, &captured!("edit-scripts"));
        self.write(SESSION, &captured!("edit-session"));
        self.write(CONFIG, &captured!("edit-config"));
        fs::write(self.root.path().join("observed"), "").unwrap();
    }

    fn write(&self, file: &str, value: &Value) {
        fs::write(
            self.root.path().join(file),
            serde_json::to_vec(value).unwrap(),
        )
        .unwrap();
    }

    fn read(&self, file: &str) -> Value {
        serde_json::from_slice(&fs::read(self.root.path().join(file)).unwrap()).unwrap()
    }

    fn mutate(&self, file: &str, body: impl FnOnce(&mut Value)) {
        let mut value = self.read(file);
        body(&mut value);
        self.write(file, &value);
    }

    fn check(&self, required: RequiredEnforcement) -> Result<InstrumentObservation, GateRefusal> {
        let dispatched = Cell::new(0);
        let result = self
            .teapot
            .with_verifier_admission(&self.session, required, |observation| {
                dispatched.set(dispatched.get() + 1);
                observation
            });
        assert_eq!(dispatched.get(), usize::from(result.is_ok()));
        self.assert_no_effectful_call();
        result
    }

    fn assert_no_effectful_call(&self) {
        assert!(
            !self.root.path().join("forbidden").exists(),
            "unexpected argv reached sink"
        );
    }
}

fn reading(surface: &EditSurface, operation: GateOperation) -> &EditSurfaceReading {
    surface
        .readings
        .iter()
        .find(|read| read.operation == operation)
        .unwrap()
}

#[test]
fn passive_gate_reads_every_frozen_surface() {
    let fixture = Fixture::new(false, false);
    let result = fixture.check(RequiredEnforcement::None).unwrap();
    assert_eq!(result.enforcement.as_str(), "unenforced");
    assert_eq!(result.identity.version.as_str(), "0.1.0");
    assert_eq!(result.identity.protocol, PROTOCOL_VERSION);
    assert_eq!(
        result.identity.engine_instance,
        fixture.teapot.engine.instance
    );
    assert_eq!(result.identity.project_id, fixture.teapot.engine.project_id);
    assert_eq!(result.edit_surface.readings.len(), 6);
    assert!(matches!(
        reading(&result.edit_surface, GateOperation::SessionShow).report.as_ref(),
        Some(EditSurfaceReport::Session(session)) if session.session == fixture.session[0]
    ));
    assert_eq!(
        reading(&result.edit_surface, GateOperation::ConfigList).report,
        Some(EditSurfaceReport::Config { settings: 1 })
    );
    assert!(result.calls.iter().all(|call| {
        call.exits
            == Exits {
                native: Some(0),
                wrapper: Some(0),
            }
    }));
    let log = fs::read_to_string(fixture.root.path().join("observed")).unwrap();
    assert_eq!(
        log.lines()
            .filter(|call| *call != "version")
            .collect::<Vec<_>>(),
        [
            PROXY,
            PASS,
            RULES,
            INTERCEPT,
            INTERCEPT_RULES,
            SCRIPTS,
            SESSION,
            CONFIG,
            PROXY
        ]
    );
}

#[test]
fn distinct_same_count_surfaces_have_distinct_evidence_digests() {
    let fixture = Fixture::new(false, false);
    let start = fixture.check(RequiredEnforcement::None).unwrap();
    fixture.mutate(CONFIG, |reply| {
        reply["settings"][0]["value"][0]["host"] = json!("localhost")
    });
    let end = fixture.check(RequiredEnforcement::None).unwrap();
    let first = reading(&start.edit_surface, GateOperation::ConfigList);
    let last = reading(&end.edit_surface, GateOperation::ConfigList);
    assert_eq!(first.report, last.report);
    assert_ne!(first.result_sha256, last.result_sha256);
    assert_eq!(
        last.result_sha256,
        Some(Sha256Digest::of(
            &serde_json::to_vec(&fixture.read(CONFIG)["settings"]).unwrap()
        ))
    );
    assert_eq!(
        reading(&start.edit_surface, GateOperation::RulesList),
        reading(&end.edit_surface, GateOperation::RulesList)
    );
}

#[test]
fn active_ending_snapshot_retains_unchanged_and_changed_surfaces() {
    let fixture = Fixture::new(false, false);
    let start = fixture.check(RequiredEnforcement::None).unwrap();
    fixture.mutate(RULES, |reply| {
        reply["rules"] = json!([
            { "n":1, "name":"first", "kind":"replace", "filter":"in:scope", "direction":"response",
              "enabled":true, "status":"running", "summary":"fixture" },
            { "n":2, "name":"second", "kind":"replace", "filter":"in:scope", "direction":"response",
              "enabled":false, "status":"off", "summary":"fixture" }
        ])
    });
    fixture.mutate(INTERCEPT, |reply| reply["intercept"]["paused"] = json!(1));
    fixture.mutate(SESSION, |reply| {
        reply["session"]["logged_out"] = json!("status:401")
    });

    let end = fixture
        .teapot
        .verifier_preflight(&fixture.session, RequiredEnforcement::None)
        .unwrap_err();
    fixture.assert_no_effectful_call();
    assert_eq!(end.reason, GateRefusalReason::ActiveRule);
    assert_eq!(end.enforcement, Some(EnforcementStatus::Unenforced));
    assert_eq!(end.policy_locked, Some(false));
    assert_eq!(
        end.edit_surface.readings.len(),
        start.edit_surface.readings.len()
    );
    assert_eq!(
        reading(&end.edit_surface, GateOperation::RulesList).report,
        Some(EditSurfaceReport::Rules(vec![
            (true, RuleStatus::Running),
            (false, RuleStatus::Off)
        ]))
    );
    assert!(matches!(
        reading(&end.edit_surface, GateOperation::InterceptStatus).report,
        Some(EditSurfaceReport::Intercept { paused: 1, .. })
    ));
    assert!(matches!(
        reading(&end.edit_surface, GateOperation::SessionShow).report.as_ref(),
        Some(EditSurfaceReport::Session(session)) if session.has_logout_rule
    ));
    assert_eq!(
        reading(&start.edit_surface, GateOperation::ConfigList),
        reading(&end.edit_surface, GateOperation::ConfigList)
    );
}

#[test]
fn partial_and_enforcement_refusals_preserve_available_evidence() {
    let fixture = Fixture::new(false, false);
    let refused = fixture.check(RequiredEnforcement::Egress).unwrap_err();
    assert_eq!(refused.reason, GateRefusalReason::EnforcementRequired);
    assert_eq!(refused.enforcement, Some(EnforcementStatus::Unenforced));
    assert_eq!(refused.edit_surface.readings.len(), 6);

    fs::write(fixture.root.path().join(SESSION), "not JSON").unwrap();
    let refused = fixture.check(RequiredEnforcement::None).unwrap_err();
    assert_eq!(refused.reason, GateRefusalReason::EditSurfaceUnestablished);
    assert_eq!(
        refused.calls.last().unwrap().operation,
        GateOperation::SessionShow
    );
    assert_eq!(refused.edit_surface.readings.len(), 4);
    assert!(
        refused
            .edit_surface
            .readings
            .iter()
            .all(|reading| reading.report.is_some())
    );

    fixture.reset();
    fixture.mutate(SESSION, |reply| {
        reply["session"]["values"] = json!({
            "sensitive": true,
            "cookies": [],
            "headers": [],
            "secrets": [{"name":"test", "value":"synthetic-marker"}],
        });
    });
    let refused = fixture.check(RequiredEnforcement::None).unwrap_err();
    assert_eq!(refused.reason, GateRefusalReason::EditSurfaceUnestablished);
    let session = reading(&refused.edit_surface, GateOperation::SessionShow);
    assert_eq!(session.report, None);
    assert_eq!(session.result_sha256, None);
}

#[test]
fn egress_requires_consistent_live_pass_and_policy_lock_reports() {
    let fixture = Fixture::new(true, true);
    let pass_file = fixture.root.path().join("owned.pass.toml");
    let pass_id = "scourge-development-fixture";
    let digest = format!(
        "sha256:{}",
        Sha256Digest::of(b"sample approved pass").as_str()
    );
    fixture.mutate("version", |version| {
        version["version"]["engine"]["pass"] = json!(pass_file);
    });
    fixture.mutate(PROXY, |proxy| {
        proxy["proxy"]["engine"] = fixture.read("version")["version"]["engine"].clone();
        let health = &mut proxy["proxy"]["health"];
        health["policy_lock"]["pass_path"] = json!(pass_file);
        health["policy_lock"]["reasons"] = json!(["enforce"]);
        health["policy_lock"]["pass"] = json!({"id":pass_id,"digest":digest});
        health["policy_lock"]["locked_keys"] = json!(["pass.*","proxy.mode"]);
        health["gate"]["pass"] = json!({
            "id":pass_id, "path":pass_file, "digest":digest, "current_digest":digest, "window":"valid",
        });
        health["gate"]["state"] = json!("bound");
        health["gate"]["settings"]["relay"] = json!("block");
    });
    fixture.mutate(PASS, |reply| {
        let pass = &mut reply["pass"];
        pass["pass_file"] = json!(pass_file);
        pass["id"] = json!(pass_id);
        pass["digest"] = json!(digest);
        pass["state"] = json!("bound");
        pass["window"] = json!("valid");
        pass["relay"] = json!("block");
        pass["enforcement"]["on"] = json!(true);
        pass["enforcement"]["code"] = json!("on");
        pass["lock"]["locked"] = json!(true);
        pass["lock"]["reasons"] = json!(["started with --enforce"]);
        pass["lock"]["locked_keys"] = json!(["pass.*", "proxy.mode"]);
    });
    let observation = fixture.check(RequiredEnforcement::Egress).unwrap();
    assert_eq!(observation.enforcement, EnforcementStatus::EgressEnforced);
    let observed = observation.pass.unwrap();
    assert_eq!(observed.id.as_str(), pass_id);
    assert_eq!(observed.file.as_str(), pass_file.to_str().unwrap());
    assert_eq!(
        observed.digest.as_str(),
        digest.strip_prefix("sha256:").unwrap()
    );
    for (file, field, wrong) in [
        (
            PROXY,
            "/proxy/health/policy_lock/reasons",
            json!(["pass-flag"]),
        ),
        (
            PROXY,
            "/proxy/health/policy_lock/pass/digest",
            json!("wrong"),
        ),
        (
            PROXY,
            "/proxy/health/gate/pass/id",
            json!("pass.development-fixture"),
        ),
        (
            PROXY,
            "/proxy/health/gate/pass/current_digest",
            json!("wrong"),
        ),
        (PROXY, "/proxy/health/gate/pass/window", json!("expired")),
        (PROXY, "/proxy/health/gate/settings/relay", json!("allow")),
        (PASS, "/pass/required", json!(true)),
        (PASS, "/pass/window", json!("expired")),
        (PASS, "/pass/relay", json!("allow")),
        (
            PASS,
            "/pass/newer_pass",
            json!({"widens":[],"narrows":["changed"]}),
        ),
    ] {
        let original = fixture.read(file);
        fixture.mutate(file, |response| {
            *response.pointer_mut(field).unwrap() = wrong
        });
        assert_eq!(
            fixture
                .check(RequiredEnforcement::Egress)
                .unwrap_err()
                .code(),
            ErrorCode::EnforcementUnavailable,
            "{field}"
        );
        fixture.write(file, &original);
    }
}

#[test]
fn missing_and_contradictory_enforcement_fields_refuse_before_edits() {
    let fixture = Fixture::new(false, false);
    let mutations = [
        ("version", "/version/answered_by", json!("cli")),
        ("version", "/version/protocol", json!(2)),
        ("version", "/version/commit", json!("wrong-build")),
        ("version", "/version/engine/instance", json!("stale")),
        ("version", "/version/engine/project_id", json!("wrong")),
        ("version", "/version/engine/project", json!("/wrong")),
        ("version", "/version/engine/build", json!("wrong")),
        ("version", "/version/engine/started_at", json!("next week")),
        ("version", "/version/engine/pid", json!(0)),
        (
            "version",
            "/version/engine/control_socket",
            json!("relative"),
        ),
        ("version", "/version/engine/enforced", json!(true)),
        ("version", "/version/engine/policy_locked", json!(true)),
        ("version", "/version/engine/mode", json!("unqualified")),
        (PROXY, "/proxy/running", json!(false)),
        (PROXY, "/proxy/project", json!("/wrong")),
        (PROXY, "/proxy/engine/listener", json!("127.0.0.1:1")),
        (PROXY, "/proxy/health/policy_lock/locked", json!(true)),
        (
            PROXY,
            "/proxy/health/policy_lock/pass_path",
            json!("/wrong"),
        ),
        (
            PROXY,
            "/proxy/health/policy_lock/locked_keys",
            json!(["pass.*"]),
        ),
        (PROXY, "/proxy/health/policy_lock/reasons", json!(["wrong"])),
        (PROXY, "/proxy/health/policy_lock/refused", json!(["wrong"])),
        (PASS, "/pass/enforcement/on", json!(true)),
        (PASS, "/pass/enforcement/code", json!("default-on")),
        (PASS, "/pass/enforcement/enforceable", json!(false)),
        (
            PASS,
            "/pass/enforcement/not_enforceable",
            json!(["loopback"]),
        ),
        (
            PASS,
            "/pass/enforcement/playpen_enforces_names",
            json!(true),
        ),
        (PASS, "/pass/lock/locked", json!(true)),
        (PASS, "/pass/state", json!("stopped")),
        (PASS, "/pass/id", json!("wrong-pass")),
        (PASS, "/pass/pass_file", json!("/wrong.pass")),
        (PASS, "/pass/digest", json!("wrong")),
        (PASS, "/pass/window", json!("expired")),
        (PASS, "/pass/stop", json!("stop-latched")),
        (PASS, "/pass/relay", json!("other")),
    ];
    for (file, field, invalid) in mutations {
        fixture.reset();
        fixture.mutate(file, |output| *output.pointer_mut(field).unwrap() = invalid);
        let failure = fixture.check(RequiredEnforcement::None).unwrap_err();
        assert_eq!(
            failure.code(),
            ErrorCode::EnforcementUnavailable,
            "{file}: {field}"
        );
        assert!(failure.calls.iter().all(|call| matches!(
            call.operation,
            GateOperation::Version | GateOperation::ProxyStatus | GateOperation::PassShow
        )));
    }
    for (file, record, key) in [
        ("version", "/version", "commit"),
        ("version", "/version/engine", "pass"),
        ("version", "/version/engine", "mode"),
        (PROXY, "/proxy/health", "policy_lock"),
        (PASS, "/pass/enforcement", "enforceable"),
        (PASS, "/pass/enforcement", "not_enforceable"),
        (PASS, "/pass", "digest"),
        (PASS, "/pass", "stop"),
    ] {
        fixture.reset();
        fixture.mutate(file, |output| {
            output
                .pointer_mut(record)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key)
                .unwrap();
        });
        assert_eq!(
            fixture.check(RequiredEnforcement::None).unwrap_err().code(),
            ErrorCode::EnforcementUnavailable,
            "{file}: {key}"
        );
    }
}

#[test]
fn edit_surface_variations_refuse_with_no_send_or_macro_dispatch() {
    use GateRefusalReason as Reason;
    let fixture = Fixture::new(false, false);
    let rule = json!({
        "n":1, "name":"test", "kind":"replace", "filter":"in:scope", "direction":"response",
        "enabled":true, "status":"running", "summary":"fixture", "matched":0
    });
    let hook =
        json!([{"event":"response_headers", "text":"response_headers", "filter":null, "line":1}]);
    let cases = [
        (RULES, "/rules", json!([rule]), Reason::ActiveRule),
        (
            RULES,
            "/rules",
            json!([{"kind":"future-rule"}]),
            Reason::EditSurfaceUnestablished,
        ),
        (
            INTERCEPT,
            "/intercept/paused",
            json!(1),
            Reason::ActiveIntercept,
        ),
        (
            INTERCEPT,
            "/intercept/paused",
            json!(null),
            Reason::EditSurfaceUnestablished,
        ),
        (
            INTERCEPT,
            "/intercept/rules",
            json!(1),
            Reason::EditSurfaceUnestablished,
        ),
        (
            INTERCEPT,
            "/intercept/active_rules",
            json!(1),
            Reason::EditSurfaceUnestablished,
        ),
        (
            INTERCEPT,
            "/intercept/change",
            json!("enabled"),
            Reason::EditSurfaceUnestablished,
        ),
        (
            INTERCEPT,
            "/intercept/on_timeout",
            json!("future"),
            Reason::EditSurfaceUnestablished,
        ),
        (
            INTERCEPT,
            "/intercept/timeout_secs",
            json!(5),
            Reason::EditSurfaceUnestablished,
        ),
        (
            INTERCEPT,
            "/intercept/enabled",
            json!(false),
            Reason::EditSurfaceUnestablished,
        ),
        (
            INTERCEPT_RULES,
            "/rules",
            json!([{"n":1,"name":"test","enabled":true,"filter":"in:scope","direction":"request"}]),
            Reason::EditSurfaceUnestablished,
        ),
        (SCRIPTS, "/scripts/0/hooks", hook, Reason::ActiveScriptHook),
        (
            SCRIPTS,
            "/scripts/0/hooks",
            json!([{"event":"future","text":"future"}]),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SCRIPTS,
            "/scripts/0/state",
            json!("future"),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SCRIPTS,
            "/scripts/0/source",
            json!("future"),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SCRIPTS,
            "/scripts/0/previous_running",
            json!(true),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SCRIPTS,
            "/scripts/0/generation",
            json!(2),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SESSION,
            "/session/name",
            json!("other"),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SESSION,
            "/session/state",
            json!("paused"),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SESSION,
            "/session/sends",
            json!("headers-to-origins"),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SESSION,
            "/session/origins",
            json!(["http://localhost"]),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SESSION,
            "/session/paused_reason",
            json!("held"),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SESSION,
            "/session/paused_evidence",
            json!([1]),
            Reason::EditSurfaceUnestablished,
        ),
        (
            SESSION,
            "/session/login",
            json!("login"),
            Reason::SessionBehavior,
        ),
        (
            SESSION,
            "/session/logged_out",
            json!("status:401"),
            Reason::SessionBehavior,
        ),
        (
            SESSION,
            "/session/csrf_tokens",
            json!(1),
            Reason::SessionBehavior,
        ),
        (
            SESSION,
            "/session/values",
            json!({}),
            Reason::EditSurfaceUnestablished,
        ),
        (
            CONFIG,
            "/settings/0/key",
            json!("proxy.unknown"),
            Reason::EditableConfiguration,
        ),
        (
            CONFIG,
            "/settings/0/value",
            json!(true),
            Reason::EditSurfaceUnestablished,
        ),
        (
            PROXY,
            "/proxy/health/policy_lock/allow_eval",
            json!(true),
            Reason::EditableConfiguration,
        ),
        (
            PROXY,
            "/proxy/health/scripts_following",
            json!(["script"]),
            Reason::EditableConfiguration,
        ),
    ];
    for (file, field, edit, reason) in cases {
        fixture.reset();
        fixture.mutate(file, |output| *output.pointer_mut(field).unwrap() = edit);
        let failure = fixture.check(RequiredEnforcement::None).unwrap_err();
        assert_eq!(failure.code(), ErrorCode::InstrumentEditsActive);
        assert_eq!(failure.reason, reason, "{file}: {field}");
    }

    for (file, object, key) in [
        (INTERCEPT, "/intercept", "change"),
        (INTERCEPT, "/intercept", "timeout_secs"),
        (SCRIPTS, "/scripts/0", "generation"),
        (SESSION, "/session", "login"),
        (SESSION, "/session", "logged_out"),
        (SESSION, "/session", "paused_reason"),
        (SESSION, "/session", "values"),
    ] {
        fixture.reset();
        fixture.mutate(file, |output| {
            output
                .pointer_mut(object)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key)
                .unwrap();
        });
        assert_eq!(
            fixture.check(RequiredEnforcement::None).unwrap_err().reason,
            Reason::EditSurfaceUnestablished,
            "{file}: {key}"
        );
    }

    fixture.reset();
    fixture.mutate(SESSION, |output| {
        output["session"]["future_edit"] = json!(true)
    });
    assert_eq!(
        fixture.check(RequiredEnforcement::None).unwrap_err().reason,
        Reason::EditSurfaceUnestablished
    );
}

#[test]
fn native_and_wrapper_failures_keep_evidence_without_retrying() {
    let fixture = Fixture::new(false, false);
    fixture.write(
        "pass-error",
        &json!({
            "error":{"code":4,"reason":"pass-not-enforceable","message":"fixture detail"},
            "advice":[]
        }),
    );
    let refusal = fixture.check(RequiredEnforcement::Egress).unwrap_err();
    assert_eq!(refusal.reason, GateRefusalReason::PassNotEnforceable);
    assert_eq!(refusal.code(), ErrorCode::EnforcementUnavailable);
    assert_eq!(
        refusal.calls.last().unwrap(),
        &GateCall {
            operation: GateOperation::PassShow,
            exits: Exits {
                native: Some(4),
                wrapper: Some(0)
            },
        }
    );

    let fixture = Fixture::new(false, false);
    let mut restarted = fixture.read("version");
    restarted["version"]["engine"]["instance"] = json!("new-instance");
    fixture.write("replace-version", &restarted);
    let refusal = fixture.check(RequiredEnforcement::None).unwrap_err();
    assert_eq!(refusal.reason, GateRefusalReason::EngineUnestablished);
    assert_eq!(
        refusal.invocation.unwrap().diagnostic().unwrap().code,
        DiagnosticCode::WrongListener
    );
    assert_eq!(
        refusal.calls.last().unwrap().operation,
        GateOperation::Version
    );

    let fixture = Fixture::new(false, false);
    fs::write(fixture.root.path().join("slow"), "").unwrap();
    let limits = process::Limits {
        deadline: Duration::from_millis(500),
        ..process::LIMITS
    };
    let refusal = fixture
        .teapot
        .verifier_preflight_with_limits(&fixture.session, RequiredEnforcement::None, limits)
        .unwrap_err();
    fixture.assert_no_effectful_call();
    assert_eq!(refusal.reason, GateRefusalReason::EditSurfaceUnestablished);
    assert_eq!(
        refusal.calls.last().unwrap().operation,
        GateOperation::RulesList
    );
    assert!(matches!(
        refusal.invocation.as_deref(),
        Some(InvocationError::DependencyUnavailable {
            transport_failure: Some(TransportFailure::Timeout),
            ..
        })
    ));

    let fixture = Fixture::new(false, false);
    let limits = process::Limits {
        stdout: 128,
        ..process::LIMITS
    };
    let refusal = fixture
        .teapot
        .verifier_preflight_with_limits(&fixture.session, RequiredEnforcement::None, limits)
        .unwrap_err();
    fixture.assert_no_effectful_call();
    assert_eq!(refusal.reason, GateRefusalReason::EngineUnestablished);
    assert!(matches!(
        refusal.invocation.as_deref(),
        Some(InvocationError::DependencyUnavailable {
            transport_failure: Some(TransportFailure::OutputLimit(OutputStream::Stdout)),
            ..
        })
    ));
}
