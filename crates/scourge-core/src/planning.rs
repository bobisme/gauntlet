//! Read-only verification planning from operator-owned runtime authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{
    domain::LeadRevision,
    engagement::{AccessAudience, ManifestRevision, RequiredEnforcement},
    ids::{EngagementId, WireText},
    json_input::MAX_SAFE_INTEGER,
    policy::{Access, Policy, PolicyContext, PolicyDecision},
    preflight::{RegisteredExecutionPlan, registered_execution_plan},
    teapot::{
        EnforcementStatus, Environment, ExecutableKind, MacroDryRun, PreviewPass, Teapot,
        accounting::{AccountingRefusal, registered_capacity},
    },
    template::{
        Claim, ClaimClass, CompiledTemplate, EngagementPin, FrozenExperiment, MissingSlot,
        Resolution, SlotBinding, SlotName, SlotValue, Templates,
    },
    wire::{
        AbsolutePath, ActionEffect, Custody, ErrorCode, Exposure, SlotSource, TargetIsolation,
        VersionedId,
    },
    workspace::{BoundWorkspace, RuntimeAuthorityError, VerifierRuntimeAuthority},
};

#[derive(Debug)]
pub struct BoundVerificationPlan {
    pub template: VersionedId,
    pub slots: BTreeMap<SlotName, PlannedSlot>,
    pub missing: Vec<MissingSlot>,
    pub effects: Vec<ActionEffect>,
    pub required_custody: Custody,
    pub required_enforcement: RequiredEnforcement,
    pub execution: Option<ExecutionPreview>,
    pub blockers: Vec<ErrorCode>,
}

#[derive(Debug, Serialize)]
pub struct PlannedSlot {
    pub value: WireText,
    pub source: PlannedSlotSource,
    pub supplied_by: WireText,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedSlotSource {
    Engagement,
    Lead,
    Preview,
}

#[derive(Debug)]
pub struct ExecutionPreview {
    pub registered: RegisteredExecutionPlan,
    pub custody: Custody,
    pub configured_sessions: BTreeMap<SlotName, ConfiguredSession>,
    /// Target account isolation requires observations beyond this passive plan.
    pub target_isolation: Option<TargetIsolation>,
    pub native_pass: Option<PreviewPass>,
    pub declared_readers: Option<AccessAudience>,
    pub policy_ceiling: PolicyCeiling,
    pub native_budget: Option<NativeBudget>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredSession {
    Exploration,
    Verifier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct NativeBudget {
    pub macro_requests: u64,
    /// Remaining units reported by the engine for the macro.
    pub units_left: Option<u64>,
    pub macro_within_ceiling: Option<bool>,
    /// Registered admission predicate using the engine macro and pass-ledger samples.
    pub compiled_requests_fit: Option<bool>,
}

/// Possible status for a future oracle result of true under the bound policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositiveStatus {
    Refuted,
    Conditional,
    Verified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyCeiling {
    pub unauthenticated: PositiveStatus,
    pub cross_principal: PositiveStatus,
}

impl PolicyCeiling {
    pub fn highest(self) -> PositiveStatus {
        self.unauthenticated.max(self.cross_principal)
    }
}

/// Resolve one plan against a selected engagement, then sample the bound
/// instrument using only local metadata and a macro dry run. No runs or request
/// keys are declared, no session is checked, and no evidence is published.
pub fn bound_verification_plan(
    workspace: &BoundWorkspace,
    engagement: &EngagementId,
    lead: &LeadRevision,
    preview_slots: &[SlotValue],
    round_count: u64,
) -> Result<BoundVerificationPlan, ErrorCode> {
    let (manifest, claim) = verification_claim(workspace, engagement, lead, preview_slots)?;
    let template = Templates::template(&claim.class).ok_or(ErrorCode::OracleUnavailable)?;
    let binding = workspace
        .resolve_verifier_runtime(engagement.as_str())
        .map_err(runtime_error)?;
    let settings = manifest.settings();

    let mut plan = BoundVerificationPlan {
        template: template.versioned_id(),
        slots: BTreeMap::new(),
        missing: Vec::new(),
        effects: template.effect_profile(),
        required_custody: settings.required_custody,
        required_enforcement: settings.required_enforcement,
        execution: None,
        blockers: Vec::new(),
    };
    match Templates::resolve(&claim, &manifest).map_err(|error| error.code())? {
        Resolution::Incomplete(form) => {
            plan.slots = describe_slots(form.resolved, preview_slots, binding);
            plan.missing = form.missing;
            plan.blockers.push(ErrorCode::SlotsIncomplete);
        }
        Resolution::Ready(experiment) => {
            let registered = registered_execution_plan(&experiment, &manifest, round_count)
                .map_err(|error| error.code())?;
            let (declared_readers, policy_ceiling) = policy_ceiling(&manifest, &experiment)?;
            // Runtime custody and target isolation are operator authority;
            // neither is inferred from executable identity or slot labels.
            let custody = binding.custody;
            let configured_sessions = experiment
                .principals
                .iter()
                .map(|(role, principal)| {
                    let source = if principal.verifier_session.is_some() {
                        ConfiguredSession::Verifier
                    } else {
                        ConfiguredSession::Exploration
                    };
                    (role.clone(), source)
                })
                .collect();
            let mut execution = ExecutionPreview {
                registered,
                custody,
                configured_sessions,
                target_isolation: Some(binding.target_isolation),
                native_pass: None,
                declared_readers,
                policy_ceiling,
                native_budget: None,
            };
            if settings.required_custody != custody {
                plan.blockers.push(ErrorCode::CapabilityUnavailable);
            }
            observe_instrument(binding, &manifest, &mut execution, &mut plan.blockers);
            plan.slots = describe_slots(experiment.slots, preview_slots, binding);
            plan.execution = Some(execution);
        }
    }
    Ok(plan)
}

/// Resolve the exact manifest and claim used by both passive planning and live
/// admission. This opens no adapter and sends no target traffic.
pub fn verification_claim(
    workspace: &BoundWorkspace,
    engagement: &EngagementId,
    lead: &LeadRevision,
    preview_slots: &[SlotValue],
) -> Result<(ManifestRevision, Claim), ErrorCode> {
    let class = lead
        .class
        .as_ref()
        .ok_or(ErrorCode::SlotsIncomplete)?
        .as_str()
        .parse::<ClaimClass>()
        .map_err(|_| ErrorCode::SchemaInvalid)?;
    let template = Templates::template(&class).ok_or(ErrorCode::OracleUnavailable)?;
    let lead_slots = caller_slots(template, lead, preview_slots)?;
    let property = lead
        .property
        .as_ref()
        .map(|value| value.as_str().parse().map_err(|_| ErrorCode::SchemaInvalid))
        .transpose()?;
    let binding = workspace
        .resolve_verifier_runtime(engagement.as_str())
        .map_err(runtime_error)?;
    let manifest = ManifestRevision::from_canonical_bytes(
        &binding.manifest.canonical_bytes,
        &binding.manifest.digest,
    )
    .map_err(|_| ErrorCode::IntegrityFailure)?;
    let claim = Claim {
        class,
        engagement: EngagementPin {
            revision: manifest.revision(),
            digest: manifest.digest().clone(),
        },
        lead: lead.lead_id.clone(),
        property,
        lead_slots,
        overrides: binding
            .principal_slots
            .iter()
            .map(|(name, slot)| SlotValue {
                name: name.clone(),
                value: slot.principal.as_str().parse().expect("validated label"),
            })
            .collect(),
    };

    Ok((manifest, claim))
}

fn runtime_error(error: RuntimeAuthorityError) -> ErrorCode {
    match error {
        RuntimeAuthorityError::Missing => ErrorCode::CapabilityUnavailable,
        RuntimeAuthorityError::Conflict => ErrorCode::IntegrityFailure,
    }
}

fn caller_slots(
    template: &CompiledTemplate,
    lead: &LeadRevision,
    preview_slots: &[SlotValue],
) -> Result<Vec<SlotValue>, ErrorCode> {
    let names = lead
        .slots
        .keys()
        .map(|name| name.as_str().parse::<SlotName>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ErrorCode::SlotConflict)?;
    for name in names
        .iter()
        .chain(preview_slots.iter().map(|slot| &slot.name))
    {
        Templates::check_lead_slot(template, name).map_err(|error| error.code())?;
    }
    let mut seen = BTreeSet::new();
    if names
        .iter()
        .chain(preview_slots.iter().map(|slot| &slot.name))
        .any(|name| !seen.insert(name))
    {
        return Err(ErrorCode::InputAmbiguous);
    }
    let mut slots = Vec::with_capacity(names.len() + preview_slots.len());
    for (name, value) in names.into_iter().zip(lead.slots.values()) {
        let value = value
            .as_str()
            .ok_or(ErrorCode::SlotConflict)?
            .parse()
            .map_err(|_| ErrorCode::SlotConflict)?;
        slots.push(SlotValue { name, value });
    }
    // Both caller channels use the resolver's untrusted supplier. Preview
    // provenance is retained only in the plan projection.
    slots.extend_from_slice(preview_slots);
    Ok(slots)
}

fn describe_slots(
    slots: BTreeMap<SlotName, SlotBinding>,
    preview_slots: &[SlotValue],
    binding: &VerifierRuntimeAuthority,
) -> BTreeMap<SlotName, PlannedSlot> {
    slots
        .into_iter()
        .map(|(name, slot)| {
            let (source, supplied_by) = match slot.source {
                SlotSource::Lead if preview_slots.iter().any(|preview| preview.name == name) => (
                    PlannedSlotSource::Preview,
                    "caller".parse().expect("static provenance"),
                ),
                SlotSource::Lead => (PlannedSlotSource::Lead, slot.supplied_by),
                _ => (
                    PlannedSlotSource::Engagement,
                    binding
                        .principal_slots
                        .get(&name)
                        .map_or(slot.supplied_by, |value| value.provenance.clone()),
                ),
            };
            (
                name,
                PlannedSlot {
                    value: slot.value,
                    source,
                    supplied_by,
                },
            )
        })
        .collect()
}

fn policy_ceiling(
    manifest: &ManifestRevision,
    experiment: &FrozenExperiment,
) -> Result<(Option<AccessAudience>, PolicyCeiling), ErrorCode> {
    let invalid = ErrorCode::IntegrityFailure;
    let property = experiment.property.as_ref().ok_or(invalid)?;
    let owner = "owner".parse::<SlotName>().expect("registered role");
    let other = "other".parse::<SlotName>().expect("registered role");
    let owner_from_lead = experiment.slots.get(&owner).ok_or(invalid)?.source == SlotSource::Lead;
    let owner = &experiment.principals.get(&owner).ok_or(invalid)?.principal;
    let other = &experiment.principals.get(&other).ok_or(invalid)?.principal;
    let policy = |exposure, actor| match Policy::allows_engagement(
        exposure,
        PolicyContext {
            manifest,
            property: &property.label,
            resource: &property.resource,
            target_version: manifest.target_version(),
            access: Access::Read,
            owner,
            actor,
        },
    ) {
        PolicyDecision::Allowed => PositiveStatus::Refuted,
        PolicyDecision::NoRule => PositiveStatus::Conditional,
        PolicyDecision::Denied if owner_from_lead => PositiveStatus::Conditional,
        PolicyDecision::Denied => PositiveStatus::Verified,
    };
    Ok((
        manifest
            .properties()
            .get(&property.label)
            .and_then(|property| property.readers),
        PolicyCeiling {
            unauthenticated: policy(Exposure::Unauthenticated, None),
            cross_principal: policy(Exposure::CrossPrincipal, Some(other)),
        },
    ))
}

fn observe_instrument(
    binding: &VerifierRuntimeAuthority,
    manifest: &ManifestRevision,
    execution: &mut ExecutionPreview,
    blockers: &mut Vec<ErrorCode>,
) {
    match sample_instrument(binding, manifest, &execution.registered) {
        Ok((pass, native)) => {
            if manifest.settings().required_enforcement == RequiredEnforcement::Egress
                && pass.enforcement != EnforcementStatus::EgressEnforced
            {
                blockers.push(ErrorCode::EnforcementUnavailable);
            }
            match native {
                Ok(native) => {
                    let (budget, blocker) = native_budget(&execution.registered, native, &pass);
                    execution.native_budget = Some(budget);
                    blockers.extend(blocker);
                }
                Err(code) => blockers.push(code),
            }
            execution.native_pass = Some(pass);
        }
        Err(code) => blockers.push(code),
    }
}

fn sample_instrument(
    binding: &VerifierRuntimeAuthority,
    manifest: &ManifestRevision,
    registered: &RegisteredExecutionPlan,
) -> Result<(PreviewPass, Result<MacroDryRun, ErrorCode>), ErrorCode> {
    use std::path::Path;
    let path = |value: &Path| -> Result<AbsolutePath, ErrorCode> {
        value
            .to_str()
            .and_then(|value| value.parse().ok())
            .ok_or(ErrorCode::IntegrityFailure)
    };
    let project = &binding.teapot;
    let teapot = Teapot::new(
        path(&project.executable)?,
        if project.wrapper {
            ExecutableKind::Wrapper
        } else {
            ExecutableKind::Native
        },
        path(&project.project)?,
        Environment {
            home: path(&project.home)?,
            config_home: project.config_home.as_deref().map(path).transpose()?,
            data_home: project.data_home.as_deref().map(path).transpose()?,
            state_home: project.state_home.as_deref().map(path).transpose()?,
            cache_home: project.cache_home.as_deref().map(path).transpose()?,
            runtime_dir: project.runtime_dir.as_deref().map(path).transpose()?,
        },
        binding.engine.clone(),
    );
    let pass_file = path(&binding.pass.path)?;
    let sample = || teapot.preview_pass(&pass_file, manifest.pass_digest());
    let pass = sample()?;
    let budget = teapot
        .dry_run_macro_with_units(&registered.macro_name, &registered.macro_session)
        .map(|observation| observation.value)
        .map_err(|error| error.code());
    if budget.is_ok() {
        // Use the latest ledger sample if the same pinned pass and engine
        // surround the dry run. Another consumer can spend units meanwhile.
        let after = sample()?;
        if after.id != pass.id || after.enforcement != pass.enforcement {
            return Err(ErrorCode::AccountingUnestablished);
        }
        return Ok((after, budget));
    }
    Ok((pass, budget))
}

fn native_budget(
    plan: &RegisteredExecutionPlan,
    native: MacroDryRun,
    pass: &PreviewPass,
) -> (NativeBudget, Option<ErrorCode>) {
    let decision = if native
        .units_left
        .is_some_and(|units| units > MAX_SAFE_INTEGER)
    {
        Err(AccountingRefusal::CountOutOfRange)
    } else {
        registered_capacity(
            plan.required_requests,
            plan.expected_macro_requests,
            native.dry_run.request_count,
            native.dry_run.within_ceiling,
            pass.requests_spent,
            pass.requests_left,
        )
    };
    let compiled_requests_fit = match decision {
        Ok(()) => Some(true),
        Err(AccountingRefusal::CeilingExceeded) => Some(false),
        Err(_) => None,
    };
    (
        NativeBudget {
            macro_requests: native.dry_run.request_count,
            units_left: native.units_left,
            macro_within_ceiling: native.dry_run.within_ceiling,
            compiled_requests_fit,
        },
        decision.err().map(AccountingRefusal::code),
    )
}

#[cfg(test)]
mod tests;
