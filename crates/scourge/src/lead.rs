use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use clap::Args;
use scourge_core::{
    domain::{LeadEvent, LeadEventKind, LeadOrigin, LeadRevision},
    engagement::EngagementDraft,
    ids::{EngagementId, LeadId, WireText},
    planning::{BoundVerificationPlan, bound_verification_plan},
    preflight::RegisteredExecutionPlan,
    response::Context,
    store::{StoreError, read::LeadDetail},
    teapot::{
        Environment, ExecutableKind,
        passive::{PassiveError, PassiveTeapot},
    },
    template::{ClaimClass, SlotKind, SlotValue, SuppliedBy, Templates},
    verification::registry::{KNOWN_MISSES, ORACLE_GUIDE_PATH, ORACLE_ID, ORACLE_VERSION},
    wire::{AbsolutePath, ActionEffect, CommitStatus, Effect, ErrorCode, ResponseV1, Timestamp},
    workspace::{BoundWorkspace, TeapotProjectAuthority},
};
use serde_json::{Value, json};

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct LeadAddArgs {
    /// A short unverified observation. Optional when --from supplies a title.
    #[arg(value_name = "TEXT")]
    pub text: Option<String>,
    /// A captured Teapot flow used only as a discovery hint.
    #[arg(long, value_name = "ID")]
    pub flow: Option<u64>,
    /// Import bounded metadata from a Teapot finding or lead.
    #[arg(long = "from", value_name = "SOURCE")]
    pub source: Option<ImportRef>,
    /// A declared Scourge claim class.
    #[arg(long = "class", value_name = "CLASS")]
    pub class: Option<String>,
    /// An operator-declared engagement property.
    #[arg(long, value_name = "PROPERTY")]
    pub property: Option<String>,
    /// A lead-supplied template slot as NAME=VALUE.
    #[arg(long = "slot", value_name = "NAME=VALUE")]
    pub slots: Vec<String>,
    /// A proposed policy statement. It is not admitted policy.
    #[arg(long, value_name = "TEXT")]
    pub policy: Option<String>,
    /// Attribution label. It grants no authority.
    #[arg(long, value_name = "ACTOR")]
    pub actor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct LeadSetArgs {
    pub id: LeadId,
    #[arg(long, value_name = "TEXT")]
    pub text: Option<String>,
    #[arg(long = "class", value_name = "CLASS")]
    pub class: Option<String>,
    #[arg(long, value_name = "PROPERTY")]
    pub property: Option<String>,
    #[arg(long = "slot", value_name = "NAME=VALUE")]
    pub slots: Vec<String>,
    #[arg(long, value_name = "TEXT")]
    pub policy: Option<String>,
    #[arg(long, value_name = "TEXT", default_value = "lead updated")]
    pub reason: String,
    #[arg(long, value_name = "ACTOR")]
    pub actor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct LeadDispositionArgs {
    pub id: LeadId,
    #[arg(long, value_name = "TEXT", default_value = "lead disposition recorded")]
    pub reason: String,
    #[arg(long, value_name = "ACTOR")]
    pub actor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct LeadDuplicateArgs {
    pub id: LeadId,
    #[arg(long = "of", value_name = "LEAD")]
    pub duplicate_of: LeadId,
    #[arg(long, value_name = "TEXT", default_value = "duplicate lead")]
    pub reason: String,
    #[arg(long, value_name = "ACTOR")]
    pub actor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImportRef {
    Finding(u64),
    Lead(u64),
}

impl ImportRef {
    fn selector(&self) -> String {
        match self {
            Self::Finding(id) => format!("teapot:{}:{id}", "finding"),
            Self::Lead(id) => format!("teapot:{}:{id}", "lead"),
        }
    }
}

impl FromStr for ImportRef {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kind, id) = value
            .strip_prefix("teapot:")
            .and_then(|value| value.split_once(':'))
            .ok_or("expected a Teapot finding selector or Teapot lead selector")?;
        let id = id.parse::<u64>().map_err(|_| "invalid Teapot object ID")?;
        match kind {
            "finding" => Ok(Self::Finding(id)),
            "lead" => Ok(Self::Lead(id)),
            _ => Err("expected a Teapot finding selector or Teapot lead selector"),
        }
    }
}

pub fn add(
    mut context: Context,
    workspace: &BoundWorkspace,
    engagement: EngagementId,
    declaration: &[u8],
    args: &LeadAddArgs,
) -> ResponseV1 {
    context.engagement = Some(engagement.clone());
    let draft = match parse_engagement(declaration) {
        Ok(value) => value,
        Err(response) => return fail(&context, response, "The engagement declaration is invalid."),
    };
    let slots = match parse_slots(&args.slots) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "A lead slot is invalid."),
    };
    let mut class = args.class.clone();
    if let Err(code) = validate_binding(&draft, class.as_deref(), args.property.as_deref(), &slots)
    {
        return fail(&context, code, binding_message(code));
    }
    // Flow intake can select the sole shipped class before it stores anything,
    // then validate explicit role slots against that class. Every other path
    // needs a declared class before a slot can be trusted.
    if class.is_none() && !slots.is_empty() && args.flow.is_none() {
        return fail(
            &context,
            ErrorCode::SlotConflict,
            "Slots require a declared class.",
        );
    }
    if args.text.is_none() && args.source.is_none() {
        return fail(
            &context,
            ErrorCode::InputRequired,
            "Provide lead text or --from.",
        );
    }
    if args.flow.is_some() && args.source.is_some() {
        return fail(
            &context,
            ErrorCode::InputAmbiguous,
            "Choose --flow or --from.",
        );
    }

    let text = args.text.as_deref().map(wire).transpose();
    if text.is_err() {
        return fail(&context, ErrorCode::UsageError, "Lead text is invalid.");
    }
    let mut text = text.ok().flatten();
    let mut origin = LeadOrigin::Local;
    let mut source_ref = None;
    let mut endpoint = None;
    let mut flow_ids = Vec::new();
    let mut producer_confidence = None;

    if let Some(source) = &args.source {
        let reader = match passive_reader(workspace, &draft) {
            Ok(reader) => reader,
            Err(code) => return fail(&context, code, "Passive Teapot metadata is unavailable."),
        };
        let imported = match source {
            ImportRef::Finding(id) => reader.finding(*id),
            ImportRef::Lead(id) => reader.lead(*id),
        };
        let imported = match imported {
            Ok(value) => value,
            Err(error) => return passive_failure(&context, error),
        };
        if text.is_none() {
            text = Some(imported.title.clone());
        }
        if class.is_none() {
            class = imported
                .class
                .as_ref()
                .map(|value| value.as_str().to_owned());
        }
        if let Err(code) =
            validate_binding(&draft, class.as_deref(), args.property.as_deref(), &slots)
        {
            return fail(&context, code, binding_message(code));
        }
        origin = LeadOrigin::Teapot;
        source_ref = wire(&source.selector()).ok();
        endpoint = Some(imported.endpoint);
        flow_ids = imported.flow_ids;
        producer_confidence = imported.producer_confidence;
    }

    let mut property = args.property.clone();
    if let Some(flow_id) = args.flow {
        let reader = match passive_reader(workspace, &draft) {
            Ok(reader) => reader,
            Err(code) => return fail(&context, code, "Passive Teapot metadata is unavailable."),
        };
        let sessions = draft
            .principals()
            .values()
            .filter_map(|principal| wire(principal.session.as_str()).ok());
        let hint = match reader.flow(flow_id, sessions) {
            Ok(value) => value,
            Err(error) => return passive_failure(&context, error),
        };
        if class.is_none() {
            let classes = Templates::registry();
            if classes.len() != 1 || !is_safe_read(hint.endpoint.as_str()) {
                return fail(
                    &context,
                    ErrorCode::InputAmbiguous,
                    "The flow does not select one safe class.",
                );
            }
            class = Some(classes[0].claim_class().as_str().to_owned());
        }
        if property.is_none() {
            property = match_property(&draft, hint.endpoint.as_str());
            if property.is_none() {
                return fail(
                    &context,
                    ErrorCode::InputAmbiguous,
                    "The flow does not select one declared property.",
                );
            }
        }
        let session_principals = draft
            .principals()
            .iter()
            .filter(|(_, principal)| principal.session.as_str() == hint.session.as_str())
            .map(|(label, _)| label.as_str())
            .collect::<Vec<_>>();
        if session_principals.is_empty() {
            return fail(
                &context,
                ErrorCode::ObjectNotFound,
                "The flow session is not declared by the engagement.",
            );
        }
        if session_principals.len() != 1 {
            return fail(
                &context,
                ErrorCode::InputAmbiguous,
                "The flow does not select one declared principal.",
            );
        }
        if let Err(code) = validate_binding(&draft, class.as_deref(), property.as_deref(), &slots) {
            return fail(&context, code, binding_message(code));
        }
        let template = registered_template(class.as_deref().expect("flow selected a class"))
            .expect("flow selected a registered class");
        let missing_roles = template
            .template
            .slots
            .iter()
            .filter(|(name, declaration)| {
                declaration.kind == SlotKind::Principal
                    && !slots.contains_key(&wire(name.as_str()).expect("registered slot"))
            })
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        if !missing_roles.is_empty() {
            return fail(
                &context,
                ErrorCode::SlotsIncomplete,
                "Flow metadata does not establish principal roles; supply every principal slot.",
            );
        }
        endpoint = Some(hint.endpoint);
        flow_ids.push(flow_id);
    }

    if let Err(code) = validate_binding(&draft, class.as_deref(), property.as_deref(), &slots) {
        return fail(&context, code, binding_message(code));
    }
    let Some(text) = text else {
        return fail(
            &context,
            ErrorCode::InputRequired,
            "Provide lead text or --from.",
        );
    };
    let actor = match actor(args.actor.as_deref()) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "The attribution label is invalid."),
    };
    let lead_id = LeadId::generate();
    let lead = LeadRevision {
        lead_id: lead_id.clone(),
        revision: 1,
        text,
        class: class
            .as_deref()
            .map(wire)
            .transpose()
            .expect("validated class"),
        property: property
            .as_deref()
            .map(wire)
            .transpose()
            .expect("validated property"),
        slots,
        proposed_policy: args.policy.as_ref().map(|value| json!(value)),
        origin,
        source_ref,
        endpoint,
        flow_ids,
        producer_confidence,
    };
    let event = match event(
        &lead_id,
        1,
        LeadEventKind::Set {
            class_changed: lead.class.is_some(),
            slots_changed: lead.property.is_some() || !lead.slots.is_empty(),
        },
        actor,
        "lead created",
    ) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "The event reason is invalid."),
    };
    let mut store = match workspace.open_coordination_writer() {
        Ok(store) => store,
        Err(error) => {
            return fail(
                &context,
                error.code(),
                "Could not open local coordination metadata.",
            );
        }
    };
    let accepted = if lead.source_ref.is_some() {
        store.create_or_reopen_imported_lead(&engagement, &lead, &event)
    } else {
        store.compare_and_set_lead_revision_with_event(&engagement, &lead, None, &event)
    };
    let accepted = match accepted {
        Ok(value) => value,
        Err(error) => return store_failure(&context, error),
    };
    let displayed = if accepted.committed {
        lead.clone()
    } else {
        drop(store);
        match detail(workspace, &engagement, &accepted.lead_id) {
            Ok(value) => value.lead,
            Err(error) => return store_failure(&context, error),
        }
    };
    let mut response = context.success(if accepted.committed {
        "lead-added"
    } else {
        "lead-reopened"
    });
    response.extensions.insert(
        "lead".into(),
        json!({
            "id": accepted.lead_id,
            "revision": accepted.revision,
        "origin": displayed.origin,
        "source_ref": displayed.source_ref,
        "producer_confidence": displayed.producer_confidence,
            "producer_confidence_is_evidence": false,
        }),
    );
    response.next.push(context.action(
        ActionEffect::None,
        [
            wire("verify").unwrap(),
            wire(accepted.lead_id.as_str()).unwrap(),
            wire("--plan").unwrap(),
        ],
    ));
    response
}

pub fn set(
    mut context: Context,
    workspace: &BoundWorkspace,
    engagement: EngagementId,
    declaration: &[u8],
    args: &LeadSetArgs,
) -> ResponseV1 {
    context.engagement = Some(engagement.clone());
    let draft = match parse_engagement(declaration) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "The engagement declaration is invalid."),
    };
    let current = match detail(workspace, &engagement, &args.id) {
        Ok(value) => value,
        Err(error) => return store_failure(&context, error),
    };
    let replacements = match parse_slots(&args.slots) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "A lead slot is invalid."),
    };
    let class = args
        .class
        .as_deref()
        .or_else(|| current.lead.class.as_ref().map(WireText::as_str));
    let property = args
        .property
        .as_deref()
        .or_else(|| current.lead.property.as_ref().map(WireText::as_str));
    if let Err(code) = validate_binding(&draft, class, property, &replacements) {
        return fail(&context, code, binding_message(code));
    }
    let mut next = current.lead.clone();
    next.revision += 1;
    if let Some(text) = args.text.as_deref() {
        let Ok(value) = wire(text) else {
            return fail(&context, ErrorCode::UsageError, "Lead text is invalid.");
        };
        next.text = value;
    }
    if let Some(class) = args.class.as_deref() {
        next.class = wire(class).ok();
    }
    if let Some(property) = args.property.as_deref() {
        next.property = wire(property).ok();
    }
    next.slots.extend(replacements);
    if let Some(policy) = &args.policy {
        next.proposed_policy = Some(json!(policy));
    }
    if let Err(code) = validate_binding(
        &draft,
        next.class.as_ref().map(WireText::as_str),
        next.property.as_ref().map(WireText::as_str),
        &next.slots,
    ) {
        return fail(&context, code, binding_message(code));
    }
    let class_changed = next.class != current.lead.class;
    let slots_changed = next.property != current.lead.property || next.slots != current.lead.slots;
    let actor = match actor(args.actor.as_deref()) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "The attribution label is invalid."),
    };
    let event = match event(
        &args.id,
        next.revision,
        LeadEventKind::Set {
            class_changed,
            slots_changed,
        },
        actor,
        &args.reason,
    ) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "The event reason is invalid."),
    };
    let mut store = match workspace.open_coordination_writer() {
        Ok(store) => store,
        Err(error) => {
            return fail(
                &context,
                error.code(),
                "Could not open local coordination metadata.",
            );
        }
    };
    match store.compare_and_set_lead_revision_with_event(
        &engagement,
        &next,
        Some(current.lead.revision),
        &event,
    ) {
        Ok(accepted) => mutation_success(&context, "lead-set", accepted.lead_id, accepted.revision),
        Err(error) => store_failure(&context, error),
    }
}

pub fn disposition(
    mut context: Context,
    workspace: &BoundWorkspace,
    engagement: EngagementId,
    args: &LeadDispositionArgs,
    kind: LeadEventKind,
    result: &'static str,
) -> ResponseV1 {
    context.engagement = Some(engagement.clone());
    let current = match detail(workspace, &engagement, &args.id) {
        Ok(value) => value,
        Err(error) => return store_failure(&context, error),
    };
    let actor = match actor(args.actor.as_deref()) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "The attribution label is invalid."),
    };
    let event = match event(&args.id, current.lead.revision, kind, actor, &args.reason) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "The event reason is invalid."),
    };
    let mut store = match workspace.open_coordination_writer() {
        Ok(store) => store,
        Err(error) => {
            return fail(
                &context,
                error.code(),
                "Could not open local coordination metadata.",
            );
        }
    };
    match store.append_lead_event(&event) {
        Ok(_) => mutation_success(&context, result, args.id.clone(), current.lead.revision),
        Err(error) => store_failure(&context, error),
    }
}

pub fn duplicate(
    mut context: Context,
    workspace: &BoundWorkspace,
    engagement: EngagementId,
    args: &LeadDuplicateArgs,
) -> ResponseV1 {
    context.engagement = Some(engagement.clone());
    let current = match detail(workspace, &engagement, &args.id) {
        Ok(value) => value,
        Err(error) => return store_failure(&context, error),
    };
    if let Err(error) = detail(workspace, &engagement, &args.duplicate_of) {
        return store_failure(&context, error);
    }
    let actor = match actor(args.actor.as_deref()) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "The attribution label is invalid."),
    };
    let event = match event(
        &args.id,
        current.lead.revision,
        LeadEventKind::Duplicate {
            lead_id: args.duplicate_of.clone(),
        },
        actor,
        &args.reason,
    ) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "The event reason is invalid."),
    };
    let mut store = match workspace.open_coordination_writer() {
        Ok(store) => store,
        Err(error) => {
            return fail(
                &context,
                error.code(),
                "Could not open local coordination metadata.",
            );
        }
    };
    match store.append_lead_event(&event) {
        Ok(_) => mutation_success(
            &context,
            "lead-duplicate",
            args.id.clone(),
            current.lead.revision,
        ),
        Err(error) => store_failure(&context, error),
    }
}

pub fn plan(
    mut context: Context,
    workspace: &BoundWorkspace,
    engagement: EngagementId,
    declaration: &[u8],
    id: &LeadId,
    round_count: u64,
    preview_slots: &[SlotValue],
) -> ResponseV1 {
    context.engagement = Some(engagement.clone());
    let draft = match parse_engagement(declaration) {
        Ok(value) => value,
        Err(code) => return fail(&context, code, "The engagement declaration is invalid."),
    };
    let current = match detail(workspace, &engagement, id) {
        Ok(value) => value,
        Err(error) => return store_failure(&context, error),
    };
    let mut experiment = json!({
        "lead_id": current.lead.lead_id,
        "lead_revision": current.lead.revision,
        "class": current.lead.class,
        "property": current.lead.property,
        "slots": current.lead.slots,
        "origin": current.lead.origin,
        "source_ref": current.lead.source_ref,
        "endpoint": current.lead.endpoint,
        "flow_ids": current.lead.flow_ids,
        "producer_confidence": current.lead.producer_confidence,
        "producer_confidence_is_evidence": false,
        "target_traffic": false,
    });
    if current.lead.class.is_some() {
        let result = bound_verification_plan(
            workspace,
            &engagement,
            &current.lead,
            preview_slots,
            round_count,
        );
        match result {
            Ok(plan) => {
                let ready = plan.execution.is_some() && plan.blockers.is_empty();
                let mut response = project_bound_plan(&context, &mut experiment, plan);
                if ready && preview_slots.is_empty() {
                    response.next.push(
                        context.action(
                            ActionEffect::Plant,
                            ["verify", id.as_str(), "--rounds", &round_count.to_string()]
                                .map(|value| wire(value).expect("verification argv")),
                        ),
                    );
                }
                project_oracle_guide(&mut experiment);
                response.extensions.insert("experiment".into(), experiment);
                return response;
            }
            Err(ErrorCode::OracleUnavailable) => {
                let mut response = unavailable_oracle(&context);
                response.extensions.insert("experiment".into(), experiment);
                return response;
            }
            // A missing runtime still permits the static form below. Every
            // class and fixed-slot refusal has already happened before this.
            Err(ErrorCode::CapabilityUnavailable)
                if !workspace
                    .authority
                    .verifier_runtime
                    .contains_key(engagement.as_str()) => {}
            Err(code) => {
                let mut response = fail(
                    &context,
                    code,
                    "The bound verification plan could not be resolved.",
                );
                response.extensions.insert("experiment".into(), experiment);
                return response;
            }
        }
    }
    if let Err(code) = validate_binding(
        &draft,
        current.lead.class.as_ref().map(WireText::as_str),
        current.lead.property.as_ref().map(WireText::as_str),
        &current.lead.slots,
    ) {
        if code == ErrorCode::CapabilityUnavailable {
            return unavailable_oracle(&context);
        }
        return fail(&context, code, binding_message(code));
    }
    let mut missing = Vec::new();
    let template = current
        .lead
        .class
        .as_ref()
        .and_then(|class| registered_template(class.as_str()).ok());
    if current.lead.class.is_none() {
        missing.push("class".to_owned());
    }
    if let Some(template) = template {
        for (name, declaration) in &template.template.slots {
            let present = match declaration.kind {
                SlotKind::Property => current.lead.property.is_some(),
                _ => current
                    .lead
                    .slots
                    .contains_key(&wire(name.as_str()).expect("registered slot")),
            };
            if !present {
                missing.push(name.as_str().to_owned());
            }
        }
    }
    if template.is_some() {
        project_oracle_guide(&mut experiment);
    }
    let complete = missing.is_empty() && template.is_some();
    let mut response = context.success("planned");
    if !complete {
        response.blockers.push(ErrorCode::SlotsIncomplete);
    }
    experiment["complete"] = json!(complete);
    experiment["missing"] = json!(missing);
    experiment["effects"] = json!(
        template
            .map(|template| template.effect_profile())
            .unwrap_or_default()
    );
    response.extensions.insert("experiment".into(), experiment);
    response
}

fn project_oracle_guide(experiment: &mut Value) {
    experiment["oracle"] = json!({
        "id": ORACLE_ID,
        "version": ORACLE_VERSION,
    });
    experiment["oracle_guide"] = json!(ORACLE_GUIDE_PATH);
    experiment["known_misses"] = json!(KNOWN_MISSES);
}

fn unavailable_oracle(context: &Context) -> ResponseV1 {
    let mut response = fail(
        context,
        ErrorCode::OracleUnavailable,
        "No compiled template matches this class. The observation stays a lead.",
    );
    response.extensions.insert(
        "supported_classes".into(),
        json!(
            Templates::registry()
                .iter()
                .map(|template| template.claim_class())
                .collect::<Vec<_>>()
        ),
    );
    response
        .extensions
        .insert("lead_remains_lead".into(), json!(true));
    response
}

fn project_bound_plan(
    context: &Context,
    experiment: &mut Value,
    plan: BoundVerificationPlan,
) -> ResponseV1 {
    let mut response = context.success("planned");
    response.blockers = plan.blockers;
    experiment["template"] = json!(plan.template);
    experiment["complete"] = json!(plan.execution.is_some());
    experiment["resolved_slots"] = json!(plan.slots);
    experiment["missing"] = json!(
        plan.missing
            .iter()
            .map(|slot| &slot.name)
            .collect::<Vec<_>>()
    );
    experiment["slot_form"] = json!(plan.missing);
    experiment["effects"] = json!(plan.effects);
    experiment["required_custody"] = json!(plan.required_custody);
    experiment["required_enforcement"] = json!(plan.required_enforcement);
    if let Some(execution) = plan.execution {
        project_recipe(experiment, &execution.registered);
        experiment["native_budget"] = json!(execution.native_budget);
        experiment["native_dry_run_requests"] = json!(
            execution
                .native_budget
                .as_ref()
                .map(|budget| budget.macro_requests)
        );
        experiment["native_request_ceiling"] =
            json!(execution.native_pass.as_ref().and_then(|pass| {
                pass.requests_spent
                    .zip(pass.requests_left)
                    .and_then(|(spent, left)| spent.checked_add(left))
            }));
        experiment["request_ceiling"] = json!(
            execution
                .native_pass
                .as_ref()
                .and_then(|pass| pass.requests_left)
        );
        experiment["pass_requests_spent"] = json!(
            execution
                .native_pass
                .as_ref()
                .and_then(|pass| pass.requests_spent)
        );
        experiment["custody"] = json!(execution.custody);
        experiment["configured_sessions"] = json!(execution.configured_sessions);
        experiment["target_isolation"] = json!(execution.target_isolation);
        experiment["enforcement"] = json!(
            execution
                .native_pass
                .as_ref()
                .map(|pass| pass.enforcement.as_str())
        );
        experiment["native_pass_id"] = json!(execution.native_pass.map(|pass| pass.id));
        experiment["declared_readers"] = json!(execution.declared_readers);
        experiment["policy_ceiling"] = json!(execution.policy_ceiling);
        experiment["highest_status"] = json!(execution.policy_ceiling.highest());
    }
    response
}

fn project_recipe(experiment: &mut Value, plan: &RegisteredExecutionPlan) {
    let dispatches = &plan.dispatches;
    experiment["rounds"] = json!(plan.round_count);
    experiment["flows_per_round"] = json!(
        dispatches
            .iter()
            .map(|dispatch| dispatch.flow)
            .collect::<Vec<_>>()
    );
    experiment["dispatches_per_round"] = json!(
        dispatches
            .iter()
            .map(|dispatch| json!({
                "flow": dispatch.flow, "actions": dispatch.actions,
            }))
            .collect::<Vec<_>>()
    );
    experiment["actions_per_round"] = json!(
        dispatches
            .iter()
            .map(|dispatch| dispatch.actions)
            .sum::<u64>()
    );
    experiment["compiled_requests_per_round"] = json!(plan.requests_per_round);
    experiment["compiled_required_requests"] = json!(plan.required_requests);
}

pub(crate) fn detail(
    workspace: &BoundWorkspace,
    engagement: &EngagementId,
    id: &LeadId,
) -> Result<LeadDetail, StoreError> {
    workspace
        .open_coordination()
        .map_err(|error| match error {
            scourge_core::workspace::WorkspaceError::Coordination(error) => error,
            _ => StoreError::ConnectionSettings,
        })?
        .snapshot(|snapshot| snapshot.scope(engagement.clone())?.lead_detail(id))
}

fn mutation_success(
    context: &Context,
    result: &'static str,
    id: LeadId,
    revision: u64,
) -> ResponseV1 {
    let mut response = context.success(result);
    response
        .extensions
        .insert("lead".into(), json!({"id": id, "revision": revision}));
    response
}

fn event(
    id: &LeadId,
    revision: u64,
    kind: LeadEventKind,
    actor: WireText,
    reason: &str,
) -> Result<LeadEvent, ErrorCode> {
    if reason.is_empty() || reason.chars().any(char::is_control) {
        return Err(ErrorCode::UsageError);
    }
    Ok(LeadEvent {
        lead_id: id.clone(),
        lead_revision: revision,
        kind,
        actor,
        reason: wire(reason).map_err(|_| ErrorCode::UsageError)?,
        evidence: Vec::new(),
        recorded_at: Timestamp::now_utc(),
    })
}

fn actor(explicit: Option<&str>) -> Result<WireText, ErrorCode> {
    let value = explicit
        .map(str::to_owned)
        .or_else(|| std::env::var("AGENT").ok())
        .unwrap_or_else(|| "local".to_owned());
    wire(&value).map_err(|_| ErrorCode::UsageError)
}

fn parse_engagement(bytes: &[u8]) -> Result<EngagementDraft, ErrorCode> {
    let draft = if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'{')
    {
        EngagementDraft::parse_json(bytes)
    } else {
        EngagementDraft::parse_toml(bytes)
    }
    .map_err(|_| ErrorCode::SchemaInvalid)?;
    draft.validate().map_err(|_| ErrorCode::SchemaInvalid)?;
    Ok(draft)
}

fn parse_slots(values: &[String]) -> Result<BTreeMap<WireText, Value>, ErrorCode> {
    let mut slots = BTreeMap::new();
    for value in values {
        let (name, value) = value.split_once('=').ok_or(ErrorCode::UsageError)?;
        let name = wire(name).map_err(|_| ErrorCode::UsageError)?;
        if slots.insert(name, json!(value)).is_some() {
            return Err(ErrorCode::SlotConflict);
        }
    }
    Ok(slots)
}

fn validate_binding(
    engagement: &EngagementDraft,
    class: Option<&str>,
    property: Option<&str>,
    slots: &BTreeMap<WireText, Value>,
) -> Result<(), ErrorCode> {
    if let Some(property) = property
        && !engagement
            .properties()
            .keys()
            .any(|label| label.as_str() == property)
    {
        return Err(ErrorCode::ObjectNotFound);
    }
    let Some(class) = class else {
        return Ok(());
    };
    let template = registered_template(class)?;
    let declarations = &template.template.slots;
    let mut principal_labels = BTreeSet::new();
    let mut principal_sessions = BTreeSet::new();
    for (name, value) in slots {
        let Some((_, declaration)) = declarations
            .iter()
            .find(|(slot, _)| slot.as_str() == name.as_str())
        else {
            return Err(ErrorCode::SlotConflict);
        };
        if declaration.kind == SlotKind::Property
            || !declaration.supplied_by.contains(&SuppliedBy::Lead)
        {
            return Err(ErrorCode::SlotConflict);
        }
        if declaration.kind == SlotKind::Principal {
            let Some(value) = value.as_str() else {
                return Err(ErrorCode::SlotConflict);
            };
            let Some((label, principal)) = engagement
                .principals()
                .iter()
                .find(|(label, _)| label.as_str() == value)
            else {
                return Err(ErrorCode::ObjectNotFound);
            };
            if !principal_labels.insert(label.as_str())
                || !principal_sessions.insert(principal.session.as_str())
            {
                return Err(ErrorCode::InputAmbiguous);
            }
        }
    }
    Ok(())
}

fn registered_template(
    class: &str,
) -> Result<&'static scourge_core::template::CompiledTemplate, ErrorCode> {
    let class = class
        .parse::<ClaimClass>()
        .map_err(|_| ErrorCode::SchemaInvalid)?;
    Templates::template(&class).ok_or(ErrorCode::CapabilityUnavailable)
}

fn match_property(engagement: &EngagementDraft, endpoint: &str) -> Option<String> {
    let path = endpoint
        .split_once(' ')
        .map_or(endpoint, |(_, endpoint)| endpoint);
    let path = path
        .split_once("://")
        .map_or(path, |(_, endpoint)| endpoint);
    let path = path.find('/').map_or("/", |index| &path[index..]);
    let segments = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<BTreeSet<_>>();
    let matches = engagement
        .properties()
        .iter()
        .filter_map(|(label, property)| {
            let label_path = label.as_str().replace('_', "-");
            let resource = property
                .resource
                .as_str()
                .strip_prefix("resource.")
                .unwrap_or(property.resource.as_str());
            (segments.contains(label_path.as_str()) || segments.contains(resource))
                .then(|| label.as_str().to_owned())
        })
        .collect::<Vec<_>>();
    (matches.len() == 1).then(|| matches[0].clone())
}

fn is_safe_read(endpoint: &str) -> bool {
    matches!(endpoint.split_whitespace().next(), Some("GET" | "HEAD"))
}

fn passive_reader(
    workspace: &BoundWorkspace,
    engagement: &EngagementDraft,
) -> Result<PassiveTeapot, ErrorCode> {
    let project = engagement.settings().instrument.project.as_str();
    let binding = workspace
        .authority
        .teapot_projects
        .get(project)
        .ok_or(ErrorCode::AuthorityRequired)?;
    build_reader(binding)
}

fn build_reader(binding: &TeapotProjectAuthority) -> Result<PassiveTeapot, ErrorCode> {
    let path = |value: &std::path::Path| -> Result<AbsolutePath, ErrorCode> {
        value
            .to_str()
            .ok_or(ErrorCode::AuthorityRequired)?
            .parse()
            .map_err(|_| ErrorCode::AuthorityRequired)
    };
    Ok(PassiveTeapot::new(
        path(&binding.executable)?,
        if binding.wrapper {
            ExecutableKind::Wrapper
        } else {
            ExecutableKind::Native
        },
        path(&binding.project)?,
        Environment {
            home: path(&binding.home)?,
            config_home: binding.config_home.as_deref().map(path).transpose()?,
            data_home: binding.data_home.as_deref().map(path).transpose()?,
            state_home: binding.state_home.as_deref().map(path).transpose()?,
            cache_home: binding.cache_home.as_deref().map(path).transpose()?,
            runtime_dir: binding.runtime_dir.as_deref().map(path).transpose()?,
        },
    ))
}

fn passive_failure(context: &Context, error: PassiveError) -> ResponseV1 {
    let message = match error {
        PassiveError::InvalidArgument => "The Teapot selector is invalid.",
        PassiveError::NotFound => "The Teapot object was not found.",
        PassiveError::Unavailable => "The passive Teapot read was unavailable.",
        PassiveError::InvalidOutput => "Teapot returned invalid passive metadata.",
        PassiveError::AmbiguousSession => "The flow did not select one declared session.",
        PassiveError::PaginationLimit => "The passive Teapot flow lookup exceeded its page bound.",
    };
    fail(context, error.code(), message)
}

fn store_failure(context: &Context, error: StoreError) -> ResponseV1 {
    fail(
        context,
        error.error_code(),
        "Could not update local coordination metadata.",
    )
}

fn binding_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::SlotConflict => "A slot is fixed, undeclared, or not lead-supplied.",
        ErrorCode::ObjectNotFound => "A declared property or principal was not found.",
        ErrorCode::InputAmbiguous => {
            "Principal slots must select distinct principals and sessions."
        }
        ErrorCode::CapabilityUnavailable => "The claim class is not implemented.",
        _ => "The lead binding is invalid.",
    }
}

fn fail(context: &Context, code: ErrorCode, message: &'static str) -> ResponseV1 {
    context.failure(code, message, CommitStatus::NotCommitted, Effect::None)
}

fn wire(value: &str) -> Result<WireText, scourge_core::ids::InvalidText> {
    value.parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scourge_core::{
        canonical::Sha256Digest,
        preflight::{PlannedDispatch, PlannedPrincipal},
    };

    #[test]
    fn plan_json_keeps_dispatch_action_counts_and_compiled_bounds() {
        let plan = RegisteredExecutionPlan {
            registry_digest: Sha256Digest::of(b"registry"),
            round_count: 2,
            dispatches: vec![
                PlannedDispatch {
                    flow: "P1",
                    principal: PlannedPrincipal::Owner,
                    session: "alice_verify".parse().unwrap(),
                    actions: 1,
                },
                PlannedDispatch {
                    flow: "C",
                    principal: PlannedPrincipal::Owner,
                    session: "alice_verify".parse().unwrap(),
                    actions: 2,
                },
            ],
            requests_per_round: 9,
            required_requests: 18,
            macro_name: "test".parse().unwrap(),
            macro_session: "alice_verify".parse().unwrap(),
            expected_macro_requests: 1,
        };
        let mut experiment = json!({});
        project_recipe(&mut experiment, &plan);
        assert_eq!(
            experiment,
            json!({
                "rounds": 2,
                "flows_per_round": ["P1", "C"],
                "dispatches_per_round": [{"flow": "P1", "actions": 1}, {"flow": "C", "actions": 2}],
                "actions_per_round": 3,
                "compiled_requests_per_round": 9,
                "compiled_required_requests": 18,
            })
        );
    }
}
