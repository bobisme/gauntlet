//! Inspection over a local coordination snapshot selected by the workspace
//! resolver. The dispatch capability contains no adapters or credentials.

use std::{
    io::{self, Write},
    str::FromStr,
    time::SystemTime,
};

use clap::{Args, ValueEnum};
use scourge_core::{
    ids::{LeadId, RunId, VerificationId, WireText},
    response::Context,
    store::{
        Result as StoreResult, StoreError,
        read::{LeadView, ReadStore, Scope},
    },
    wire::{
        AbsolutePath, ActionEffect, Advice, AdviceLevel, CommitStatus, Effect, ErrorCode,
        FindingStatus, ResponseV1, RunState,
    },
    workspace::{BoundWorkspace, WorkspaceError},
};
use serde_json::{Value, json};

use crate::{Command, Format, Invocation, doctor, unbound_status, workspace_failure};

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum Depth {
    Title,
    Summary,
    Full,
}

impl Depth {
    fn as_str(self) -> &'static str {
        match self {
            Self::Title => "title",
            Self::Summary => "summary",
            Self::Full => "full",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ObjectId {
    Lead(LeadId),
    Finding(LeadId),
    Run(RunId),
    Record(VerificationId),
    TeapotFlow(u64),
}

impl FromStr for ObjectId {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = "expected a lead, finding, run, record or Teapot flow ID";
        if let Some(id) = value.strip_prefix("finding:") {
            return id.parse().map(Self::Finding).map_err(|_| invalid);
        }
        if let Some(number) = value.strip_prefix("teapot:flow:") {
            if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid);
            }
            return number.parse().map(Self::TeapotFlow).map_err(|_| invalid);
        }
        match value.as_bytes().first() {
            Some(b'L') => value.parse().map(Self::Lead).map_err(|_| invalid),
            Some(b'R') => value.parse().map(Self::Run).map_err(|_| invalid),
            Some(b'V') => value.parse().map(Self::Record).map_err(|_| invalid),
            _ => Err(invalid),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum Noun {
    Leads,
    Findings,
    Runs,
}

impl Noun {
    fn as_str(self) -> &'static str {
        match self {
            Self::Leads => "leads",
            Self::Findings => "findings",
            Self::Runs => "runs",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Args)]
pub struct ListArgs {
    /// Which collection to list.
    #[arg(value_enum, default_value = "leads")]
    noun: Noun,
    /// Filter by a run state, lead disposition, or finding status.
    #[arg(long, value_name = "STATUS")]
    status: Option<String>,
    /// Maximum number of objects on a page (1–100).
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=100))]
    limit: u32,
    /// Skip this many matching IDs in lexicographic order.
    #[arg(long, default_value_t = 0)]
    offset: u32,
}

impl ListArgs {
    pub(crate) fn valid_status(&self) -> bool {
        self.status.as_deref().is_none_or(|status| match self.noun {
            Noun::Leads => matches!(
                status,
                "open" | "withdrawn" | "duplicate" | "deferred" | "blocked"
            ),
            Noun::Findings => FindingStatus::try_from(status.to_owned()).is_ok(),
            Noun::Runs => RunState::try_from(status.to_owned()).is_ok(),
        })
    }
}

/// The workspace resolver supplies both paths after validating its operator
/// binding. The read handler never gets the executable, socket, or evidence
/// locators in that binding.
pub struct BoundReads {
    workspace: AbsolutePath,
    coordination: AbsolutePath,
}

impl BoundReads {
    pub fn from_resolved_paths(workspace: AbsolutePath, coordination: AbsolutePath) -> Self {
        Self {
            workspace,
            coordination,
        }
    }
}

/// Run the shipped local read path after binding. An unresolved scope can only
/// return orientation or an error and never opens a coordination database.
pub fn dispatch_read(invocation: Invocation, bound: Option<&BoundReads>) -> ResponseV1 {
    dispatch_read_at(invocation, bound, SystemTime::now())
}

/// Use one clock value for all check ages in the command's snapshot.
pub fn dispatch_read_at(
    invocation: Invocation,
    bound: Option<&BoundReads>,
    now: SystemTime,
) -> ResponseV1 {
    if !matches!(
        invocation.command,
        Command::Show { .. } | Command::List(_) | Command::Doctor
    ) {
        return unbound_status(invocation);
    }
    let Some(bound) = bound else {
        return unbound_status(invocation);
    };

    let mut context = Context::for_command(invocation.command.as_str());
    context.workspace = Some(bound.workspace.clone());

    let store = match ReadStore::open(bound.coordination.as_str().as_ref()) {
        Ok(store) => store,
        Err(error) => return store_failure(&context, error),
    };
    inspect(invocation, context, &store, now)
}

pub(crate) fn dispatch_workspace(
    mut invocation: Invocation,
    mut context: Context,
    selected: &BoundWorkspace,
) -> ResponseV1 {
    let engagement =
        match selected.select_engagement(invocation.engagement.as_ref().map(|id| id.as_str())) {
            Ok((engagement, _)) => engagement.parse().expect("validated engagement name"),
            Err(error @ WorkspaceError::EngagementRequired) => {
                let mut response = workspace_failure(&context, error);
                let mut names: Vec<_> = selected.engagements().take(21).collect();
                let more = names.len() > 20;
                names.truncate(20);
                response
                    .extensions
                    .insert("engagements".into(), json!(names));
                response
                    .extensions
                    .insert("more_engagements".into(), json!(more));
                return response;
            }
            Err(error) => return workspace_failure(&context, error),
        };
    invocation.engagement = Some(engagement);
    match selected.open_coordination() {
        Ok(store) => inspect(invocation, context, &store, SystemTime::now()),
        Err(WorkspaceError::CoordinationUnavailable) => {
            context.engagement = invocation.engagement;
            let mut response = context.blocked(Vec::new());
            unavailable(
                &mut response,
                "coordination-unavailable",
                "The bound workspace has no initialized coordination store.",
            );
            response
        }
        Err(error) => {
            context.engagement = invocation.engagement;
            workspace_failure(&context, error)
        }
    }
}

fn inspect(
    invocation: Invocation,
    mut context: Context,
    store: &ReadStore,
    now: SystemTime,
) -> ResponseV1 {
    let read = || {
        store.snapshot(|snapshot| {
            let engagement = if let Some(engagement) = invocation.engagement {
                engagement
            } else {
                let mut engagements = snapshot.engagements(21)?;
                if engagements.len() != 1 {
                    let mut response = context.failure(
                        ErrorCode::EngagementRequired,
                        "Select an engagement with --engagement.",
                        CommitStatus::NotCommitted,
                        Effect::None,
                    );
                    let more = engagements.len() > 20;
                    engagements.truncate(20);
                    response
                        .extensions
                        .insert("engagements".into(), json!(engagements));
                    response
                        .extensions
                        .insert("more_engagements".into(), json!(more));
                    return Ok(response);
                }
                engagements.pop().expect("exactly one engagement")
            };
            let scope = snapshot.scope(engagement)?;
            context.engagement = Some(scope.engagement().clone());
            match invocation.command {
                Command::Show {
                    id: Some(id),
                    depth,
                    rederive,
                } => show(&context, &scope, id, depth, rederive),
                Command::List(args) => list(&context, &scope, args),
                Command::Doctor => doctor::read(&context, &scope, now),
                _ => unreachable!("only parsed read commands use the read store"),
            }
        })
    };

    read().unwrap_or_else(|error| store_failure(&context, error))
}

fn store_failure(context: &Context, error: StoreError) -> ResponseV1 {
    let code = error.error_code();
    let message = match code {
        ErrorCode::ObjectNotFound => "No such object in this scope.",
        ErrorCode::ConflictingRun => "The local coordination store is busy. Retry this read.",
        _ => "Could not read local coordination metadata.",
    };
    context.failure(code, message, CommitStatus::NotCommitted, Effect::None)
}

fn show(
    context: &Context,
    scope: &Scope<'_>,
    id: ObjectId,
    depth: Depth,
    rederive: bool,
) -> StoreResult<ResponseV1> {
    let mut response = context.success("shown");
    response
        .extensions
        .insert("depth".into(), json!(depth.as_str()));
    match id {
        ObjectId::Lead(id) => {
            let lead = scope.lead(&id)?;
            response.extensions.insert("lead".into(), lead_json(&lead));
            if lead.has_records {
                finding_unavailable(&mut response);
            }
        }
        ObjectId::Finding(id) => {
            // The index is an existence hint, never the §5.1 status authority.
            if !scope.lead(&id)?.has_records {
                return Err(StoreError::SelectorNotFound);
            }
            response.extensions.insert("finding_id".into(), json!(id));
            finding_unavailable(&mut response);
        }
        ObjectId::Run(id) => {
            let details = scope.run(&id)?;
            response.request_key = Some(details.request_key);
            response.run = Some(details.view.run);
            response
                .extensions
                .insert("run_effects".into(), json!(details.view.effects));
            if matches!(depth, Depth::Full) {
                response
                    .extensions
                    .insert("experiment_digest".into(), json!(details.experiment_digest));
            }
        }
        ObjectId::Record(id) => {
            let record = scope.record(&id)?;
            response.extensions.insert(
                "record".into(),
                json!({
                    "id": record.id,
                    "sequence": record.sequence,
                    "run_id": record.run,
                    "lead_id": record.lead,
                    "record_digest": record.digest,
                }),
            );
        }
        ObjectId::TeapotFlow(id) => {
            let flow = scope.flow(id)?;
            response.extensions.insert(
                "flow".into(),
                json!({
                    "id": format!("teapot:flow:{id}"),
                    "flow_id": id,
                    "run_id": flow.run,
                    "step_number": flow.number,
                    "completeness": flow.completeness,
                }),
            );
        }
    }
    if rederive {
        unavailable(
            &mut response,
            "rederive-unavailable",
            "Fresh derivation from retained originals is unavailable.",
        );
    }
    Ok(response)
}

fn lead_json(lead: &LeadView) -> Value {
    // Lead text, policy and slots can contain arbitrary evidence and secrets.
    // No unstructured content enters this projection at any depth.
    json!({
        "id": lead.id,
        "revision": lead.revision,
        "has_records": lead.has_records,
        "text_withheld": true,
    })
}

fn list(context: &Context, scope: &Scope<'_>, args: ListArgs) -> StoreResult<ResponseV1> {
    let mut response = context.success("listed");
    let limit = args.limit + 1;
    let noun = args.noun.as_str();
    let mut items = match args.noun {
        Noun::Leads if args.status.is_none() => scope
            .leads(limit, args.offset)?
            .iter()
            .map(lead_json)
            .collect::<Vec<_>>(),
        Noun::Runs => {
            let state = args
                .status
                .clone()
                .map(RunState::try_from)
                .transpose()
                .expect("run status was validated during parsing");
            let runs = scope.runs(state, limit, args.offset)?;
            let effects: serde_json::Map<_, _> = runs
                .iter()
                .take(args.limit as usize)
                .map(|item| (item.run.id.as_str().to_owned(), json!(item.effects)))
                .collect();
            response
                .extensions
                .insert("run_effects".into(), effects.into());
            runs.into_iter().map(|item| json!(item.run)).collect()
        }
        Noun::Findings => {
            finding_unavailable(&mut response);
            return Ok(response);
        }
        Noun::Leads => {
            unavailable(
                &mut response,
                "lead-status-unavailable",
                "Lead dispositions are unavailable for filtering.",
            );
            return Ok(response);
        }
    };
    let more = items.len() > args.limit as usize;
    items.truncate(args.limit as usize);
    response.extensions.insert(noun.into(), json!(items));
    let next_offset = more.then(|| args.offset.checked_add(args.limit)).flatten();
    response.extensions.insert(
        "page".into(),
        json!({
            "limit": args.limit,
            "offset": args.offset,
            "next_offset": next_offset,
        }),
    );
    if let Some(next_offset) = next_offset {
        let mut argv = vec![
            text("list"),
            text(noun),
            text("--limit"),
            text(&args.limit.to_string()),
            text("--offset"),
            text(&next_offset.to_string()),
        ];
        if let Some(status) = args.status {
            argv.extend([text("--status"), text(&status)]);
        }
        response.next.push(context.action(ActionEffect::None, argv));
    }
    Ok(response)
}

fn finding_unavailable(response: &mut ResponseV1) {
    unavailable(
        response,
        "finding-status-unavailable",
        "Finding status and applicability are unavailable without the record and oracle status source.",
    );
}

fn unavailable(response: &mut ResponseV1, kind: &'static str, message: &'static str) {
    response.result = Some(text("blocked"));
    if !response
        .blockers
        .contains(&ErrorCode::CapabilityUnavailable)
    {
        response.blockers.push(ErrorCode::CapabilityUnavailable);
    }
    response.advice.push(Advice {
        level: AdviceLevel::Warn,
        r#type: kind.parse().expect("valid advice type"),
        message: text(message),
    });
}

fn text(string: &str) -> WireText {
    string.parse().expect("valid response text")
}

/// Render only the whitelisted metadata the read dispatcher publishes. All
/// opaque text fields remain withheld for both human output formats.
pub(crate) fn write_objects(
    response: &ResponseV1,
    format: Format,
    stream: &mut impl Write,
) -> io::Result<bool> {
    if !matches!(
        response.command.as_ref().map(WireText::as_str),
        Some("show" | "list")
    ) {
        return Ok(false);
    }
    let title = response.extensions.get("depth").and_then(Value::as_str) == Some("title");
    let full = response.extensions.get("depth").and_then(Value::as_str) == Some("full");
    for noun in ["lead", "record", "flow"] {
        if let Some(item) = response.extensions.get(noun) {
            if title {
                write_fields(&[item["id"].as_str().unwrap_or("-"), noun], format, stream)?;
            } else {
                write_object(noun, item, None, format, stream)?;
            }
            if full && noun == "record" {
                write_detail(
                    item["id"].as_str(),
                    "record digest",
                    item.get("record_digest"),
                    format,
                    stream,
                )?;
            }
            return Ok(true);
        }
    }
    if let Some(id) = response
        .extensions
        .get("finding_id")
        .and_then(Value::as_str)
    {
        write_fields(&[id, "finding"], format, stream)?;
        return Ok(true);
    }
    if let Some(run) = &response.run {
        let id = run.id.as_str();
        let run = json!(run);
        write_object(
            "run",
            &run,
            response.extensions.get("run_effects"),
            format,
            stream,
        )?;
        if full {
            write_detail(
                Some(id),
                "experiment digest",
                response.extensions.get("experiment_digest"),
                format,
                stream,
            )?;
        }
        return Ok(true);
    }

    for (plural, noun) in [("leads", "lead"), ("runs", "run")] {
        if let Some(items) = response.extensions.get(plural).and_then(Value::as_array) {
            if items.is_empty() {
                write_fields(&[plural, "0"], format, stream)?;
            }
            for item in items {
                let effects = response
                    .extensions
                    .get("run_effects")
                    .and_then(|map| map.get(item["id"].as_str().unwrap_or("-")));
                write_object(noun, item, effects, format, stream)?;
            }
            return Ok(true);
        }
    }

    Ok(false)
}

fn write_detail(
    id: Option<&str>,
    label: &str,
    detail: Option<&Value>,
    format: Format,
    stream: &mut impl Write,
) -> io::Result<()> {
    if let (Some(id), Some(detail)) = (id, detail.and_then(Value::as_str)) {
        write_fields(&[id, label, detail], format, stream)?;
    }
    Ok(())
}

fn write_object(
    noun: &str,
    item: &Value,
    effects: Option<&Value>,
    format: Format,
    stream: &mut impl Write,
) -> io::Result<()> {
    let field = |name| item[name].as_str().unwrap_or("-");
    let mut fields = vec![field("id"), noun];
    let number;
    let flags;
    let effect;
    match noun {
        "lead" => {
            number = format!("rev {}", item["revision"]);
            fields.extend([number.as_str(), "text withheld"]);
            if item["has_records"].as_bool() == Some(true) {
                fields.push("records linked");
            }
        }
        "run" => {
            flags = item["flags"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",");
            effect = format!("effects={}", effects.and_then(Value::as_str).unwrap_or("-"));
            fields.extend([
                field("state"),
                field("oracle_result"),
                field("reproduction"),
                field("cleanup"),
                if flags.is_empty() { "-" } else { &flags },
                &effect,
            ]);
        }
        "record" => {
            number = format!("seq {}", item["sequence"]);
            fields.extend([number.as_str(), field("run_id"), field("lead_id")]);
        }
        "flow" => {
            number = format!("step {}", item["step_number"]);
            fields.extend([field("run_id"), number.as_str(), field("completeness")]);
        }
        _ => unreachable!("only known read projections are rendered"),
    }
    write_fields(&fields, format, stream)
}

fn write_fields(fields: &[&str], format: Format, stream: &mut impl Write) -> io::Result<()> {
    if format == Format::Pretty {
        writeln!(stream, "{}  │  {}", fields[0], fields[1..].join("  │  "))
    } else {
        writeln!(stream, "{}", fields.join("  "))
    }
}
