//! Bounded read-only orientation over a resolved operator binding.

use std::io::{self, Write};

use clap::{Args, ValueEnum};
use scourge_core::{
    canonical::Sha256Digest,
    engagement::EngagementDraft,
    ids::{EngagementId, VerificationId},
    response::Context,
    store::{
        checks::Stage,
        entry::{AttentionReason, EntrySnapshot, TeapotObservation, teapot_route_digest},
    },
    template::Templates,
    wire::{Action, ActionEffect, Diagnostic, ErrorCode, ResponseV1, Transport, TransportKind},
    workspace::{BoundWorkspace, WorkspaceError},
};
use serde_json::{Value, json};

use crate::{Format, shell_quote, workspace_failure};

pub(crate) const ORIENTATION: &str = "scourge: record security leads and verify findings with independent controls.\nNew workspace: scourge init PATH --engagement FILE";
const LEAD_CAVEAT: &str =
    "A lead is an observation. Verification requires independent controls and retained evidence.";
const STATE_CAVEAT: &str = "Pass validity and current findings require separate evidence. Shared custody allows the same account to alter its local state.";
const TEAPOT_CAVEAT: &str =
    "A Teapot finding or Teapot lead is a discovery input. Verification requires Scourge evidence.";
const UNKNOWN_EFFECTS: &str = "Effects are unknown. Review the run before continuing.";
const PENDING_CLEANUP: &str = "Cleanup remains owed. Review the run before continuing.";
const BROKEN_CHAIN: &str = "The local record chain is broken. Resolve integrity before continuing.";
const UNREADABLE_STORE: &str =
    "Coordination state is unavailable. Counts and run state are withheld.";
const UNCHECKED_TRANSPORT: &str = "Transport reachability is unestablished.";
const UNREADABLE_OBSERVATIONS: &str = "Recorded transport observations are unavailable.";
const SIZE: usize = 2048;
const BRIEF_LABELS: usize = 4;
const BRIEF_LABEL_BYTES: usize = 110;
const DETAIL_LABELS: usize = 12;
const DETAIL_LABEL_BYTES: usize = 360;

#[derive(Args, Clone, Debug, Default, Eq, PartialEq)]
pub struct EntryArgs {
    /// Read a page of setup, engagement names, records or transport state.
    #[arg(long)]
    details: Option<Details>,
    /// Skip this many entries in the selected detail view.
    #[arg(long, requires = "details", default_value_t = 0)]
    offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Details {
    Setup,
    Engagements,
    Records,
    Transport,
}

pub(crate) fn unbound(context: &Context) -> ResponseV1 {
    let mut response = context.blocked(vec![ErrorCode::WorkspaceUnbound]);
    response
        .extensions
        .insert("orientation".into(), ORIENTATION.into());
    response
        .extensions
        .insert("caveats".into(), json!([LEAD_CAVEAT]));
    response
        .next
        .push(action(&Context::default(), &["init", "--help"]));
    response
}

pub(crate) fn bound(
    mut context: Context,
    workspace: &BoundWorkspace,
    selector: Option<&EngagementId>,
    args: &EntryArgs,
) -> ResponseV1 {
    if context.workspace.is_none() {
        let mut response = context.blocked(vec![ErrorCode::CapabilityUnavailable]);
        response.extensions.insert(
            "caveats".into(),
            json!(["The workspace path cannot be represented in a command argument."]),
        );
        response
            .next
            .push(action(&Context::default(), &["status", "--help"]));
        return response;
    }
    let (name, declaration) = match workspace.select_engagement(selector.map(EngagementId::as_str))
    {
        Ok(selected) => selected,
        Err(WorkspaceError::EngagementRequired) => {
            return choose_engagement(context, workspace, args);
        }
        Err(error) => return workspace_failure(&context, error),
    };
    let engagement = name.parse().expect("validated engagement identity");
    context.engagement = Some(engagement);
    if args.details == Some(Details::Engagements) {
        return choose_engagement(context, workspace, args);
    }
    let draft = if declaration
        .iter()
        .copied()
        .find(|b| !b.is_ascii_whitespace())
        == Some(b'{')
    {
        EngagementDraft::parse_json(declaration)
    } else {
        EngagementDraft::parse_toml(declaration)
    };
    let Ok(draft) = draft else {
        return workspace_failure(&context, WorkspaceError::InvalidEngagement);
    };
    let route = Route::from_workspace(workspace, draft.settings().instrument.project.as_str());
    let snapshot = load(workspace, &context, route.as_ref(), args);
    project(&context, args, &draft, route.as_ref(), snapshot)
}

fn choose_engagement(context: Context, workspace: &BoundWorkspace, args: &EntryArgs) -> ResponseV1 {
    let mut response = context.success("bound");
    let mut caveats = vec![LEAD_CAVEAT];
    if context.engagement.is_none() {
        response.blockers.push(ErrorCode::EngagementRequired);
        caveats.push("Select an engagement with its operator-assigned name.");
    }
    let page = page(workspace.engagements(), args, Details::Engagements);
    response
        .extensions
        .insert("engagements".into(), json!(page.names));
    response
        .extensions
        .insert("engagements_omitted".into(), json!(page.omitted));
    response
        .extensions
        .insert("engagements_offset".into(), json!(page.offset));
    let next = if args.details != Some(Details::Engagements) {
        action(&context, &["status", "--details", "engagements"])
    } else if let Some(offset) = page.next_offset {
        action(
            &context,
            &[
                "status",
                "--details",
                "engagements",
                "--offset",
                &offset.to_string(),
            ],
        )
    } else {
        action(&Context::default(), &["engagement", "show", "--help"])
    };
    response.next.push(next);
    response.extensions.insert("caveats".into(), json!(caveats));
    response
}

struct Route<'a> {
    kind: TransportKind,
    endpoint: &'a str,
    digest: Sha256Digest,
}

impl<'a> Route<'a> {
    fn from_workspace(workspace: &'a BoundWorkspace, project: &str) -> Option<Self> {
        let (kind, endpoint) = [
            (TransportKind::Broker, "broker"),
            (TransportKind::Proxy, "proxy"),
            (TransportKind::TeapotProject, "teapot"),
        ]
        .into_iter()
        .find_map(|(kind, key)| Some((kind, workspace.authority.sockets.get(key)?.to_str()?)))?;
        let digest = teapot_route_digest(kind, endpoint, project);
        Some(Self {
            kind,
            endpoint,
            digest,
        })
    }
}

#[derive(Default)]
struct CachedStatus {
    snapshot: EntrySnapshot,
    teapot: Option<TeapotObservation>,
    transport_checked: bool,
    diagnostic: Option<Diagnostic>,
    transport_blocker: Option<ErrorCode>,
    record_ids: Vec<VerificationId>,
}

fn load(
    workspace: &BoundWorkspace,
    context: &Context,
    route: Option<&Route<'_>>,
    args: &EntryArgs,
) -> Result<CachedStatus, ErrorCode> {
    let engagement = context.engagement.clone().expect("selected engagement");
    let store = workspace
        .open_coordination()
        .map_err(|error| error.code())?;
    store
        .snapshot(|snapshot| {
            let scope = snapshot.scope(engagement)?;
            let mut status = CachedStatus {
                snapshot: scope.entry_status()?,
                ..CachedStatus::default()
            };
            if args.details == Some(Details::Records) {
                let offset = u32::try_from(args.offset).unwrap_or(u32::MAX);
                status.record_ids = scope.entry_record_ids(DETAIL_LABELS as u32, offset)?;
            }
            if let Some(route) = route {
                let observations = scope.teapot_entry_observation(&route.digest);
                let checks = scope.recorded_checks();
                status.transport_blocker = observations
                    .as_ref()
                    .err()
                    .or(checks.as_ref().err())
                    .map(|error| error.error_code());
                status.teapot = observations.ok().flatten();
                let describe = checks
                    .ok()
                    .flatten()
                    .into_iter()
                    .flatten()
                    .find(|view| view.check.stage == Stage::Describe);
                status.transport_checked = describe.is_some();
                status.diagnostic = describe.and_then(|view| view.check.diagnostic());
            }
            Ok(status)
        })
        .map_err(|error| error.error_code())
}

fn project(
    context: &Context,
    args: &EntryArgs,
    draft: &EngagementDraft,
    route: Option<&Route<'_>>,
    cached: Result<CachedStatus, ErrorCode>,
) -> ResponseV1 {
    let mut response = context.success("bound");
    let mut caveats = vec![LEAD_CAVEAT, STATE_CAVEAT];
    let mut next = action(context, &["status", "--details", "setup"]);
    if let Some(route) = route {
        response.transport = Some(Transport {
            kind: route.kind,
            endpoint: route.endpoint.parse().expect("validated transport path"),
            action: action(context, &["doctor"]),
        });
    } else {
        response.blockers.push(ErrorCode::AuthorityRequired);
    }

    if matches!(args.details, None | Some(Details::Setup)) {
        let principals = page(
            draft.principals().keys().map(|name| name.as_str()),
            args,
            Details::Setup,
        );
        let properties = page(
            draft.properties().keys().map(|name| name.as_str()),
            args,
            Details::Setup,
        );
        let classes = page(
            Templates::registry()
                .iter()
                .map(|template| template.claim_class().as_str()),
            args,
            Details::Setup,
        );
        response.extensions.insert(
            "setup".into(),
            json!({
                "required_custody": draft.settings().required_custody,
                "pass_ref": draft.settings().pass_ref,
                "principals": principals.names,
                "principals_omitted": principals.omitted,
                "properties": properties.names,
                "properties_omitted": properties.omitted,
                "classes": classes.names,
                "classes_omitted": classes.omitted,
                "offset": properties.offset,
            }),
        );
        if args.details == Some(Details::Setup) {
            next = [
                principals.next_offset,
                properties.next_offset,
                classes.next_offset,
            ]
            .into_iter()
            .flatten()
            .min()
            .map_or_else(
                || action(context, &["list", "leads"]),
                |offset| {
                    action(
                        context,
                        &[
                            "status",
                            "--details",
                            "setup",
                            "--offset",
                            &offset.to_string(),
                        ],
                    )
                },
            );
        }
    } else {
        next = action(context, &["doctor"]);
    }

    match cached {
        Ok(CachedStatus {
            snapshot,
            teapot,
            transport_checked,
            diagnostic,
            transport_blocker,
            record_ids,
        }) => {
            if let Some(diagnostic) = diagnostic {
                response.blockers.push(ErrorCode::DependencyUnavailable);
                response.diagnostics.push(diagnostic);
                next = action(context, &["doctor"]);
            } else if let Some(blocker) = transport_blocker {
                response.blockers.push(blocker);
                caveats.push(UNREADABLE_OBSERVATIONS);
                next = action(context, &["doctor"]);
            } else if route.is_some() && !transport_checked {
                caveats.push(UNCHECKED_TRANSPORT);
            }
            if snapshot.broken_chain {
                caveats.push(BROKEN_CHAIN);
                response.blockers.push(ErrorCode::IntegrityFailure);
            }
            if args.details.is_none() {
                response.extensions.insert(
                    "counts".into(),
                    json!({
                        "leads": snapshot.leads,
                        "leads_omitted": snapshot.leads,
                        "linked_records": snapshot.linked_records,
                        "linked_records_omitted": snapshot.linked_records,
                        "verified_findings": null,
                        "runs": snapshot.runs,
                        "runs_omitted": snapshot.runs,
                        "attention_runs": snapshot.attention_runs,
                    }),
                );
                if snapshot.leads > 0
                    && response.diagnostics.is_empty()
                    && transport_blocker.is_none()
                {
                    next = action(context, &["list", "leads"]);
                }
            }
            if let Some(record) = teapot.filter(|_| response.diagnostics.is_empty()) {
                record_teapot(&mut response, &mut caveats, record, args);
            }
            if args.details == Some(Details::Records) {
                let ids = record_ids
                    .iter()
                    .map(VerificationId::as_str)
                    .filter(|id| safe_machine_label(id))
                    .collect::<Vec<_>>();
                response.extensions.insert(
                    "local_chain".into(),
                    json!({
                        "head_sequence": snapshot.head_sequence,
                        "linked_records": snapshot.linked_records,
                        "record_ids": ids,
                        "omitted": snapshot.linked_records.saturating_sub(ids.len() as u64),
                        "offset": args.offset,
                    }),
                );
                let page_end = args.offset.saturating_add(record_ids.len());
                if !record_ids.is_empty() && (page_end as u64) < snapshot.linked_records {
                    next = action(
                        context,
                        &[
                            "status",
                            "--details",
                            "records",
                            "--offset",
                            &page_end.to_string(),
                        ],
                    );
                } else if let Some(id) = ids.first() {
                    next = action(context, &["show", id]);
                }
            }
            if let Some(attention) = snapshot.attention {
                match attention.reason {
                    AttentionReason::UnknownEffects => {
                        caveats.push(UNKNOWN_EFFECTS);
                        response.blockers.push(ErrorCode::EffectUnknown);
                    }
                    AttentionReason::PendingCleanup => {
                        caveats.push(PENDING_CLEANUP);
                        response.blockers.push(ErrorCode::ConflictingRun);
                    }
                    AttentionReason::BrokenChain => {}
                }
                next = match attention.run {
                    Some(run) if safe_machine_label(run.as_str()) => {
                        action(context, &["show", run.as_str()])
                    }
                    Some(_) => action(context, &["list", "runs"]),
                    None if args.details == Some(Details::Records) => next,
                    None => action(context, &["status", "--details", "records"]),
                };
            }
        }
        Err(code) => {
            caveats.push(UNREADABLE_STORE);
            response.blockers.push(code);
            next = action(context, &["list", "runs"]);
        }
    }
    response.extensions.insert("caveats".into(), json!(caveats));
    response.next.push(next);
    response
}

fn record_teapot(
    response: &mut ResponseV1,
    caveats: &mut Vec<&'static str>,
    record: TeapotObservation,
    args: &EntryArgs,
) {
    if args.details == Some(Details::Transport)
        || record.unrecorded_findings.unwrap_or(0) > 0
        || record.unrecorded_leads.unwrap_or(0) > 0
    {
        response.extensions.insert(
            "teapot".into(),
            json!({
                "source": "operator-bound-teapot",
                "observed_at": record.observed_at,
                "evidence_digest": record.evidence_digest,
                "unrecorded_findings": record.unrecorded_findings,
                "unrecorded_leads": record.unrecorded_leads,
            }),
        );
        caveats.push(TEAPOT_CAVEAT);
    }
}

fn action(context: &Context, args: &[&str]) -> Action {
    context.action(
        ActionEffect::None,
        args.iter().map(|arg| arg.parse().unwrap()),
    )
}

struct Page<'a> {
    names: Vec<&'a str>,
    omitted: usize,
    offset: usize,
    next_offset: Option<usize>,
}

fn safe_machine_label(value: &str) -> bool {
    value.len() <= 96
}

fn page<'a>(names: impl Iterator<Item = &'a str>, args: &EntryArgs, detail: Details) -> Page<'a> {
    let (offset, limit, budget) = if args.details == Some(detail) {
        (args.offset, DETAIL_LABELS, DETAIL_LABEL_BYTES)
    } else {
        (0, BRIEF_LABELS, BRIEF_LABEL_BYTES)
    };
    let mut page = Page {
        names: Vec::new(),
        omitted: 0,
        offset,
        next_offset: None,
    };
    let mut bytes = 0;
    for (index, name) in names.enumerate() {
        let width = visible(name).len();
        if index < offset || !safe_machine_label(name) || width > budget {
            page.omitted += 1;
        } else if page.names.len() < limit && bytes + width <= budget && page.next_offset.is_none()
        {
            page.names.push(name);
            bytes += width;
        } else {
            page.omitted += 1;
            page.next_offset.get_or_insert(index);
        }
    }
    page
}

fn visible(value: &str) -> String {
    value.chars().flat_map(char::escape_debug).collect()
}

pub(crate) fn write_human(
    response: &ResponseV1,
    format: Format,
    out: &mut impl Write,
) -> io::Result<bool> {
    if response.command.as_ref().map(|word| word.as_str()) != Some("status")
        || !response.extensions.contains_key("caveats")
    {
        return Ok(false);
    }
    let fields = &response.extensions;
    let mut required = Vec::new();
    let mut detail = Vec::new();
    if let Some(orientation) = fields.get("orientation").and_then(Value::as_str) {
        detail.push(orientation.into());
    }
    if let Some(engagement) = &response.engagement {
        let name = visible(engagement.as_str());
        let name = if name.len() <= 160 {
            &name
        } else {
            "name omitted. See scourge status --details engagements"
        };
        detail.push(format!("Engagement  {name}"));
    }
    if let Some(counts) = fields.get("counts") {
        detail.push(format!(
            "State  {} recorded leads, {} linked verification records, {} runs ({} need attention)\nOmitted  {} leads via scourge list leads, {} linked verification records via scourge status --details records, {} runs via scourge list runs",
            counts["leads"], counts["linked_records"], counts["runs"], counts["attention_runs"],
            counts["leads_omitted"], counts["linked_records_omitted"], counts["runs_omitted"],
        ));
    }
    if let Some(setup) = fields.get("setup") {
        detail.push(format!(
            "Required custody  {}\nPass  {} (validity unestablished)",
            setup["required_custody"].as_str().unwrap_or("unknown"),
            setup["pass_ref"].as_str().unwrap_or("unknown"),
        ));
        for (label, key) in [
            ("Principals", "principals"),
            ("Properties", "properties"),
            ("Classes", "classes"),
        ] {
            detail.push(render_page(
                label,
                &setup[key],
                &setup[format!("{key}_omitted")],
                "scourge status --details setup",
            ));
        }
    }
    if let Some(engagements) = fields.get("engagements") {
        detail.push(render_page(
            "Engagements",
            engagements,
            &fields["engagements_omitted"],
            "scourge status --details engagements",
        ));
    }
    if let Some(chain) = fields.get("local_chain") {
        detail.push(format!(
            "Local chain  head sequence {}, {} linked records",
            chain["head_sequence"], chain["linked_records"]
        ));
        detail.push(render_page(
            "Verification records",
            &chain["record_ids"],
            &chain["omitted"],
            "scourge status --details records --offset N",
        ));
    }
    if let Some(transport) = &response.transport {
        let endpoint = visible(transport.endpoint.as_str());
        let endpoint = if endpoint.len() <= 160 {
            &endpoint
        } else {
            "endpoint omitted. See scourge status --details transport"
        };
        let kind = json!(transport.kind);
        detail.push(format!(
            "Transport  {} {}\nRecorded checks  scourge doctor",
            kind.as_str().unwrap_or("unknown"),
            endpoint
        ));
    }
    if let Some(teapot) = fields.get("teapot") {
        let timestamp = teapot["observed_at"].as_str().unwrap_or("unavailable");
        if teapot.get("unrecorded_findings").is_some() {
            detail.push(format!("Recorded {timestamp}  Teapot finding count {}, Teapot lead count {} (without Scourge leads at capture). See scourge status --details transport",
                teapot["unrecorded_findings"].as_u64().map_or_else(|| "unavailable".into(), |n| n.to_string()),
                teapot["unrecorded_leads"].as_u64().map_or_else(|| "unavailable".into(), |n| n.to_string()),
            ));
        } else {
            detail.push(format!("Transport observation recorded {timestamp}"));
        }
    }

    for caveat in fields["caveats"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        required.push(format!("Caveat  {caveat}"));
    }
    for blocker in &response.blockers {
        let label = if format == Format::Pretty {
            "[BLOCKED]"
        } else {
            "Blocker"
        };
        required.push(format!("{label}  {}", blocker.as_str()));
    }
    for diagnostic in &response.diagnostics {
        let code = json!(diagnostic.code);
        required.push(format!("Transport  {}", code.as_str().unwrap_or("unknown")));
    }
    if let Some(action) = response.next.first() {
        let words: Vec<_> = action.argv.iter().map(|word| word.as_str()).collect();
        let label = words[0];
        let args = &words[3..];
        let mut command = render_command(label, args);
        if command.len() > 600 {
            let mut local = args;
            while let Some(flag) = local.first() {
                local = match *flag {
                    "--workspace" | "--engagement" => &local[2..],
                    flag if flag.starts_with("--engagement=") => &local[1..],
                    _ => break,
                };
            }
            command = format!(
                "{} (use the selected workspace and engagement)",
                render_command(label, local)
            );
        }
        required.push(format!("Next  {command}"));
    }
    let mut remaining = SIZE.saturating_sub(required.iter().map(|line| line.len() + 1).sum());
    let omissions =
        |count| format!("Omitted  {count} sections. Detail commands via scourge status --help");
    let sections_exceed_budget =
        detail.iter().map(|line| line.len() + 1).sum::<usize>() > remaining;
    if sections_exceed_budget {
        remaining = remaining.saturating_sub(omissions(detail.len()).len() + 1);
    }
    let mut omitted_sections = 0;
    for line in detail {
        if line.len() < remaining {
            writeln!(out, "{line}")?;
            remaining -= line.len() + 1;
        } else {
            omitted_sections += 1;
        }
    }
    if omitted_sections > 0 {
        writeln!(out, "{}", omissions(omitted_sections))?;
    }
    for line in required {
        writeln!(out, "{line}")?;
    }
    Ok(true)
}

fn render_command(label: &str, args: &[&str]) -> String {
    std::iter::once(label)
        .chain(args.iter().copied())
        .map(|value| {
            if value
                .chars()
                .any(|ch| ch.is_control() || ch.escape_debug().count() > 1)
            {
                let escaped = value
                    .bytes()
                    .map(|byte| format!("\\x{byte:02x}"))
                    .collect::<String>();
                format!("$'{escaped}'")
            } else {
                shell_quote(value)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_page(label: &str, names: &Value, omitted: &Value, route: &str) -> String {
    let names = names
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(visible)
        .collect::<Vec<_>>()
        .join(", ");
    if omitted.as_u64().unwrap_or(0) > 0 {
        format!("{label}  {names} ({omitted} omitted via {route})")
    } else if names.is_empty() {
        format!("{label}  none")
    } else {
        format!("{label}  {names}")
    }
}
