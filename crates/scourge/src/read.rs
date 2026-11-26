//! Inspection over a local coordination snapshot selected by the workspace
//! resolver. Full finding projections may also use operator-bound Evidence.

use std::{
    io::{self, Write},
    str::FromStr,
    time::SystemTime,
};

use clap::{Args, ValueEnum};
use scourge_core::{
    evidence::EvidenceError,
    ids::{EngagementId, LeadId, RunId, VerificationId, WireText},
    response::Context,
    store::{
        RequestScope, Result as StoreResult, StoreError,
        read::{LeadView, ReadStore, RecoverySelector, Scope},
    },
    verification::{
        coherent_read::{self, CoherentRead, Freshness, ReadError},
        status::{Audience, Status},
    },
    wire::{
        AbsolutePath, ActionEffect, Advice, AdviceLevel, CommitStatus, Effect, ErrorCode,
        FindingStatus, FindingSummary, ResponseV1, RunState,
    },
    workspace::{BoundWorkspace, RuntimeAuthorityError, VerifierEvidenceError, WorkspaceError},
};
use serde_json::{Value, json};

use crate::{Command, Format, Invocation, doctor, run, unbound_status, workspace_failure};

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
    binding: Option<WireText>,
}

impl BoundReads {
    pub fn from_resolved_paths(workspace: AbsolutePath, coordination: AbsolutePath) -> Self {
        Self {
            workspace,
            coordination,
            binding: None,
        }
    }

    /// Bind standalone read dispatch to the service-issued workspace identity
    /// needed by request-key recovery. Ordinary object reads do not use it.
    pub fn from_resolved_paths_and_binding(
        workspace: AbsolutePath,
        coordination: AbsolutePath,
        binding: WireText,
    ) -> Self {
        Self {
            workspace,
            coordination,
            binding: Some(binding),
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
        Command::Show { .. }
            | Command::List(_)
            | Command::Doctor
            | Command::Run {
                action: Some(run::RunCommand::Show(_))
            }
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
    inspect(
        invocation,
        context,
        &store,
        now,
        None,
        bound.binding.as_ref(),
    )
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
        Ok(store) => inspect(
            invocation,
            context,
            &store,
            SystemTime::now(),
            Some(selected),
            None,
        ),
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
    selected: Option<&BoundWorkspace>,
    standalone_binding: Option<&WireText>,
) -> ResponseV1 {
    let (depth, rederive) = match &invocation.command {
        Command::Show {
            depth, rederive, ..
        } => (*depth, *rederive),
        _ => (Depth::Summary, false),
    };
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
                    return Ok((response, None));
                }
                engagements.pop().expect("exactly one engagement")
            };
            let scope = snapshot.scope(engagement)?;
            context.engagement = Some(scope.engagement().clone());
            match invocation.command {
                Command::Show { id: Some(id), .. } => show(&context, &scope, id, depth),
                Command::List(args) => {
                    list(&context, &scope, args).map(|response| (response, None))
                }
                Command::Doctor => {
                    doctor::read(&context, &scope, now).map(|response| (response, None))
                }
                Command::Run {
                    action: Some(run::RunCommand::Show(args)),
                } => {
                    let binding = standalone_binding.ok_or(StoreError::SelectorNotFound)?;
                    let request_scope =
                        RequestScope::new(scope.engagement().clone(), binding.clone());
                    let selector = match (&args.run, &args.request_key) {
                        (Some(run), None) => RecoverySelector::Run(run),
                        (None, Some(key)) => RecoverySelector::RequestKey(key),
                        _ => unreachable!("Clap requires exactly one run selector"),
                    };
                    let recovery = snapshot.recover(&request_scope, selector)?;
                    Ok((run::show_response(&context, &recovery), None))
                }
                _ => unreachable!("only parsed read commands use the read store"),
            }
        })
    };

    let (mut response, finding_lead) = match read() {
        Ok(result) => result,
        Err(error) => return store_failure(&context, error),
    };
    if let Some(lead) = finding_lead {
        // Coherent reads release their coordination snapshot before consulting
        // Evidence and check that the two named states overlapped.
        let finding = match (depth, selected, context.engagement.as_ref()) {
            (Depth::Full, Some(selected), Some(engagement)) => {
                read_finding(selected, store, engagement, &lead)
            }
            _ => Ok(None),
        };
        match finding {
            Ok(finding) => {
                if !finding.is_some_and(|view| attach_finding(&mut response, view)) {
                    finding_unavailable(&mut response);
                }
            }
            Err(code) => return finding_failure(&context, code),
        }
    }
    if response.ok && rederive {
        unavailable(
            &mut response,
            "rederive-unavailable",
            "Fresh derivation from retained originals is unavailable.",
        );
    }
    response
}

fn read_finding(
    selected: &BoundWorkspace,
    store: &ReadStore,
    engagement: &EngagementId,
    lead: &LeadId,
) -> Result<Option<CoherentRead>, ErrorCode> {
    let evidence = match selected.open_verifier_evidence(engagement) {
        Ok(evidence) => evidence,
        Err(VerifierEvidenceError::Authority(RuntimeAuthorityError::Missing)) => return Ok(None),
        Err(VerifierEvidenceError::Authority(RuntimeAuthorityError::Conflict)) => {
            return Err(ErrorCode::IntegrityFailure);
        }
        Err(VerifierEvidenceError::Evidence(EvidenceError::ChangedSnapshot)) => return Ok(None),
        Err(VerifierEvidenceError::Evidence(error)) => {
            return Err(ReadError::Evidence(error).code());
        }
    };
    match coherent_read::read_qualified(store, &evidence, lead, Audience::Internal, 3) {
        Ok(view) if view.computed.status == Status::IntegrityFailure => {
            Err(ErrorCode::IntegrityFailure)
        }
        Ok(view) => Ok(Some(view)),
        Err(ReadError::NoCoherentRead) => Ok(None),
        Err(error) => Err(error.code()),
    }
}

/// Reopen the evaluator-owned publication through the same qualified coherent
/// read used by `show finding --depth full`.
pub(crate) fn coherent_badge(
    selected: &BoundWorkspace,
    engagement: &EngagementId,
    lead: &LeadId,
) -> Result<scourge_core::wire::FindingSummary, ErrorCode> {
    let store = selected.open_coordination().map_err(|error| error.code())?;
    let coherent =
        read_finding(selected, &store, engagement, lead)?.ok_or(ErrorCode::IntegrityFailure)?;
    if coherent.freshness != Freshness::Current || coherent.has_unassessed_objection() {
        return Err(ErrorCode::IntegrityFailure);
    }
    coherent.finding.ok_or(ErrorCode::IntegrityFailure)
}

fn finding_failure(context: &Context, code: ErrorCode) -> ResponseV1 {
    let message = match code {
        ErrorCode::IntegrityFailure => {
            "Finding evidence or its trusted binding failed an integrity check."
        }
        ErrorCode::DependencyUnavailable => "Could not open the qualified finding evidence.",
        _ => "Could not assemble a coherent finding read.",
    };
    context.failure(code, message, CommitStatus::NotCommitted, Effect::None)
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
) -> StoreResult<(ResponseV1, Option<LeadId>)> {
    let mut response = context.success("shown");
    let mut finding_lead = None;
    response
        .extensions
        .insert("depth".into(), json!(depth.as_str()));
    match id {
        ObjectId::Lead(id) => {
            let lead = scope.lead(&id)?;
            response.extensions.insert("lead".into(), lead_json(&lead));
            if lead.has_records {
                finding_lead = Some(id);
            }
        }
        ObjectId::Finding(id) => {
            // The index is an existence hint, never the §5.1 status authority.
            if !scope.lead(&id)?.has_records {
                return Err(StoreError::SelectorNotFound);
            }
            response.extensions.insert("finding_id".into(), json!(id));
            finding_lead = Some(id);
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
            let mut details = json!({
                "id": record.id,
                "sequence": record.sequence,
                "run_id": record.run,
                "lead_id": record.lead,
                "record_digest": record.digest,
            });
            if depth == Depth::Full
                && record.oracle_id.as_deref()
                    == Some(scourge_core::verification::registry::ORACLE_ID)
                && record.oracle_version.as_deref()
                    == Some(scourge_core::verification::registry::ORACLE_VERSION)
                && record.oracle_digest.as_ref()
                    == Some(&scourge_core::verification::registry::oracle_digest())
            {
                if let Some(limitations) = record.limitations {
                    details["known_misses"] = json!(limitations);
                }
                details["oracle_guide"] =
                    json!(scourge_core::verification::registry::ORACLE_GUIDE_PATH);
            }
            response.extensions.insert("record".into(), details);
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
    Ok((response, finding_lead))
}

fn attach_finding(response: &mut ResponseV1, coherent: CoherentRead) -> bool {
    if coherent.freshness != Freshness::Current {
        return false;
    }
    if coherent.has_unassessed_objection() {
        unavailable(
            response,
            "finding-objection-unassessed",
            "Finding status is withheld while a recorded objection awaits assessment.",
        );
        return true;
    }
    let (Some(finding), Some(revision)) = (coherent.finding, coherent.lead_revision) else {
        return false;
    };
    if let Some(lead) = response.extensions.get_mut("lead") {
        // Replace the revision from the existence lookup with the one that
        // actually accompanied the badge.
        lead["revision"] = json!(revision);
    }
    response.finding = Some(finding);
    true
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
            if noun == "record" && !title {
                if let Some(guide) = item.get("oracle_guide").and_then(Value::as_str) {
                    write_fields(
                        &[item["id"].as_str().unwrap_or("-"), "oracle guide", guide],
                        format,
                        stream,
                    )?;
                }
                if let Some(misses) = item.get("known_misses").and_then(Value::as_array) {
                    for miss in misses.iter().filter_map(Value::as_str) {
                        write_fields(
                            &[item["id"].as_str().unwrap_or("-"), "known miss", miss],
                            format,
                            stream,
                        )?;
                    }
                }
            }
            if full
                && noun == "lead"
                && let Some(finding) = &response.finding
            {
                write_finding(finding, format, stream)?;
            }
            return Ok(true);
        }
    }
    if full && let Some(finding) = &response.finding {
        write_finding(finding, format, stream)?;
        return Ok(true);
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

fn write_finding(
    finding: &FindingSummary,
    format: Format,
    stream: &mut impl Write,
) -> io::Result<()> {
    let finding = json!(finding);
    let field = |name| finding[name].as_str().unwrap_or("-");
    let id = field("id");
    // An unavailable archived oracle can carry arbitrary wire text.
    let oracle = field("oracle").escape_default().to_string();
    write_fields(
        &[id, "finding", field("status"), field("applicability")],
        format,
        stream,
    )?;
    for (label, value) in [
        ("profile", field("profile")),
        ("oracle", oracle.as_str()),
        ("validation", field("validation")),
        ("exposure", field("exposure")),
        ("custody", field("custody")),
        ("target isolation", field("target_isolation")),
        ("enforcement", field("enforcement")),
        ("policy source", field("policy_source")),
        ("status record", field("status_record")),
        ("deciding record", field("deciding_record")),
    ] {
        write_fields(&[id, label, value], format, stream)?;
    }
    Ok(())
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
#[cfg(test)]
mod tests {
    use super::*;
    use scourge_core::verification::{coherent_read::SnapshotName, status};
    use scourge_core::{canonical::Sha256Digest, wire};

    #[test]
    fn full_finding_uses_frozen_json_and_human_fields() {
        let expected = json!({
            "id": "L-1",
            "status": "verified",
            "applicability": "unestablished",
            "profile": "runtime-controlled.v1",
            "oracle": "web.private-object-read.v1",
            "validation": "deterministic",
            "exposure": "cross_principal",
            "custody": "shared",
            "target_isolation": "separate_principals",
            "enforcement": "unenforced",
            "policy_source": "engagement",
            "status_record": "V-1",
            "deciding_record": "V-2",
        });
        let finding: FindingSummary = serde_json::from_value(expected.clone()).unwrap();
        let view = |freshness| CoherentRead {
            name: SnapshotName {
                coordination_revision: 11,
                chain: wire::Checkpoint {
                    engagement: "test".parse().unwrap(),
                    sequence: 2,
                    record_digest: Some(Sha256Digest::of(b"second record")),
                },
                evidence: json!({"sequence": 3}),
                registry_version: coherent_read::registry_version(),
            },
            freshness,
            computed: status::Computed {
                status: status::Status::Verified,
                applicability: status::Applicability::Unestablished,
                status_record: finding.status_record.clone(),
                deciding_record: finding.deciding_record.clone(),
                qualified: true,
            },
            standing_true: Vec::new(),
            events: Vec::new(),
            lead_revision: Some(5),
            finding: Some(finding.clone()),
        };
        let mut response = Context::for_command("show").success("shown");
        response.extensions.insert("depth".into(), json!("full"));
        response.extensions.insert(
            "lead".into(),
            json!({"id": "L-1", "revision": 4, "has_records": true, "text_withheld": true}),
        );
        assert!(!attach_finding(&mut response, view(Freshness::Historical)));
        assert!(response.finding.is_none());
        assert_eq!(response.extensions["lead"]["revision"], 4);
        assert!(attach_finding(&mut response, view(Freshness::Current)));
        assert_eq!(response.extensions["lead"]["revision"], 5);
        let envelope: ResponseV1 = wire::from_slice(&wire::to_vec(&response).unwrap()).unwrap();
        assert_eq!(json!(envelope)["finding"], expected);
        assert_eq!(envelope.effects, Effect::None);
        assert!(envelope.blockers.is_empty());

        let mut rendered = Vec::new();
        assert!(write_objects(&envelope, Format::Text, &mut rendered).unwrap());
        let badge = concat!(
            "L-1  finding  verified  unestablished\n",
            "L-1  profile  runtime-controlled.v1\n",
            "L-1  oracle  web.private-object-read.v1\n",
            "L-1  validation  deterministic\n",
            "L-1  exposure  cross_principal\n",
            "L-1  custody  shared\n",
            "L-1  target isolation  separate_principals\n",
            "L-1  enforcement  unenforced\n",
            "L-1  policy source  engagement\n",
            "L-1  status record  V-1\n",
            "L-1  deciding record  V-2\n",
        );
        assert_eq!(
            String::from_utf8(rendered).unwrap(),
            format!("L-1  lead  rev 5  text withheld  records linked\n{badge}")
        );
        let mut finding_view = envelope;
        finding_view.extensions.remove("lead");
        finding_view
            .extensions
            .insert("finding_id".into(), json!("L-1"));
        let mut rendered = Vec::new();
        assert!(write_objects(&finding_view, Format::Pretty, &mut rendered).unwrap());
        assert_eq!(
            String::from_utf8(rendered).unwrap(),
            badge.replace("  ", "  │  ")
        );

        let mut stale = view(Freshness::Current);
        stale.computed.status = Status::NeedsReview;
        let archived_oracle = "archived\u{1b}[2J\nname.v\u{009b}1\u{202e}";
        let stale_finding = stale.finding.as_mut().unwrap();
        stale_finding.status = FindingStatus::NeedsReview;
        stale_finding.oracle = archived_oracle.parse().unwrap();
        assert!(attach_finding(&mut finding_view, stale));
        let wire = json!(finding_view);
        assert_eq!(wire["finding"]["status"], "needs_review");
        assert_eq!(wire["finding"]["oracle"], archived_oracle);
        assert_eq!(wire["finding"]["status_record"], "V-1");
        assert_eq!(wire["finding"]["deciding_record"], "V-2");
        let escaped_badge = badge.replacen("verified", "needs_review", 1).replace(
            "web.private-object-read.v1",
            r"archived\u{1b}[2J\nname.v\u{9b}1\u{202e}",
        );
        for (format, expected) in [
            (Format::Pretty, escaped_badge.replace("  ", "  │  ")),
            (Format::Text, escaped_badge),
        ] {
            let mut rendered = Vec::new();
            assert!(write_objects(&finding_view, format, &mut rendered).unwrap());
            assert_eq!(String::from_utf8(rendered).unwrap(), expected);
        }

        let mut objected = view(Freshness::Current);
        objected.events.push(scourge_core::domain::LeadEvent {
            lead_id: "L-1".parse().unwrap(),
            lead_revision: 5,
            kind: scourge_core::domain::LeadEventKind::Objection,
            actor: "private-actor".parse().unwrap(),
            reason: "private-reason".parse().unwrap(),
            evidence: Vec::new(),
            recorded_at: "2026-11-25T07:00:00Z".parse().unwrap(),
        });
        let mut withheld = Context::for_command("show").success("shown");
        assert!(attach_finding(&mut withheld, objected));
        assert!(withheld.finding.is_none());
        let wire = json!(withheld);
        assert_eq!(wire["advice"][0]["type"], "finding-objection-unassessed");
        assert!(!wire.to_string().contains("private-"));
    }
}
