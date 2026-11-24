//! Passive diagnostics from the scoped coordination snapshot.

use std::{
    io::{self, Write},
    time::SystemTime,
};

use scourge_core::{
    response::Context,
    store::{
        Result,
        checks::{CheckView, Stage},
        read::Scope,
    },
    wire::{Advice, AdviceLevel, DiagnosticV1, ErrorCode, ResponseV1},
};
use serde_json::{Value, json};

use crate::Format;

const MAX_CORRELATION_BYTES: usize = 128;

pub(crate) fn read(context: &Context, scope: &Scope<'_>, now: SystemTime) -> Result<ResponseV1> {
    let observations = scope.recorded_checks()?;
    let mut response = context.success("checked");
    if observations.is_none() {
        response = context.blocked(vec![ErrorCode::CapabilityUnavailable]);
        response.advice.push(advice(
            "recorded-checks-unavailable",
            "This coordination schema has no recorded checks.",
        ));
    }
    let mut checks = Vec::with_capacity(Stage::ALL.len());
    let mut future_timestamp = false;
    for stage in Stage::ALL {
        let observation = observations
            .as_ref()
            .and_then(|rows| rows.iter().find(|view| view.check.stage == stage));
        if let Some(view) = observation {
            let age = view.check.age_seconds(now);
            future_timestamp |= age.is_none();
            if let Some(diagnostic) = view.check.diagnostic() {
                response.diagnostics.push(diagnostic);
            }
            checks.push(recorded_check(view, age));
        } else {
            checks.push(json!({
                "stage": stage.as_str(),
                "state": if observations.is_some() { "missing" } else { "unavailable" },
                "observed_at": null, "age_seconds": null, "timestamp_in_future": false,
                "code": null, "native_exit": null, "wrapper_exit": null,
                "run_id": null, "request_key": null, "correlation_withheld": false,
            }));
        }
    }
    if !response.diagnostics.is_empty() {
        response.result = Some("blocked".parse().expect("valid result"));
        response.blockers.push(ErrorCode::DependencyUnavailable);
    }
    if future_timestamp {
        response.advice.push(advice(
            "check-clock-skew",
            "An observation timestamp is later than the current clock.",
        ));
    }
    response.extensions.insert("checks".into(), json!(checks));
    Ok(response)
}

fn recorded_check(view: &CheckView, age_seconds: Option<u64>) -> Value {
    let check = &view.check;
    let run = check.run_id.as_ref().map(|run| run.as_str());
    let key = view.request_key.as_ref().map(|key| key.as_str());
    let withheld = run
        .into_iter()
        .chain(key)
        .any(|id| id.len() > MAX_CORRELATION_BYTES);
    json!({
        "stage": check.stage.as_str(),
        "state": if check.code.is_some() { "failed" } else { "passed" },
        "observed_at": check.observed_at,
        "age_seconds": age_seconds,
        "timestamp_in_future": age_seconds.is_none(),
        "code": check.code,
        "native_exit": check.native_exit,
        "wrapper_exit": check.wrapper_exit,
        "run_id": run.filter(|_| !withheld),
        "request_key": key.filter(|_| !withheld),
        "correlation_withheld": withheld,
    })
}

fn advice(kind: &'static str, message: &'static str) -> Advice {
    Advice {
        level: AdviceLevel::Warn,
        r#type: kind.parse().expect("valid advice type"),
        message: message.parse().expect("valid advice message"),
    }
}

/// An observation can belong to an earlier invocation than doctor itself.
/// Use its bounded, already-scoped correlation when writing that diagnostic.
pub(crate) fn correlate_event(response: &ResponseV1, event: &mut DiagnosticV1) {
    if response.command.as_ref().map(|command| command.as_str()) != Some("doctor") {
        return;
    }
    let Some(check) = response
        .extensions
        .get("checks")
        .and_then(Value::as_array)
        .and_then(|checks| {
            checks.iter().find(|check| {
                check["stage"].as_str() == Some(event.diagnostic.stage.as_str())
                    && check["state"] == "failed"
            })
        })
    else {
        return;
    };
    event.run_id = check["run_id"].as_str().and_then(|id| id.parse().ok());
    event.request_key = check["request_key"]
        .as_str()
        .and_then(|key| key.parse().ok());
}

pub(crate) fn write_checks(
    response: &ResponseV1,
    format: Format,
    stream: &mut impl Write,
) -> io::Result<bool> {
    let Some(checks) = response.extensions.get("checks").and_then(Value::as_array) else {
        return Ok(false);
    };
    if response.command.as_ref().map(|command| command.as_str()) != Some("doctor") {
        return Ok(false);
    }
    let separator = if format == Format::Pretty {
        "  │  "
    } else {
        "  "
    };
    for check in checks {
        let field = |key| check[key].as_str().unwrap_or("-");
        let state = field("state");
        let mut fields = vec![field("stage").to_owned(), state.to_owned()];
        if let Some(observed_at) = check["observed_at"].as_str() {
            let age = check["age_seconds"].as_u64().map_or_else(
                || "age=unknown".to_owned(),
                |seconds| format!("age={seconds}s"),
            );
            fields.extend([age, observed_at.to_owned()]);
            if state == "failed" {
                fields.push(field("code").to_owned());
            }
            for label in ["native_exit", "wrapper_exit"] {
                if let Some(exit) = check[label].as_i64() {
                    fields.push(format!("{label}={exit}"));
                }
            }
            if let Some(run) = check["run_id"].as_str() {
                fields.extend([run.to_owned(), field("request_key").to_owned()]);
            }
            if check["correlation_withheld"].as_bool() == Some(true) {
                fields.push("correlation withheld".to_owned());
            }
        }
        writeln!(stream, "{}", fields.join(separator))?;
    }
    Ok(true)
}
