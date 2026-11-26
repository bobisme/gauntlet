//! Owned local setup for the M1 development-fixture tutorial.

mod instrument;
mod process;
mod supervisor;

use std::{
    env, fs, io,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use clap::Args;
use scourge_core::{
    engagement::{EngagementDraft, ManifestRevision, PassPin, RequiredEnforcement},
    evidence::{Completion, Evidence, EvidenceError},
    ids::RunId,
    response::Context,
    rounds::TargetOrigin,
    teapot::{BoundEngine, Teapot},
    wire::{
        ActionEffect, CommitStatus, Custody, Effect, EnvironmentKind, ErrorCode, ResponseV1,
        TargetIsolation,
    },
    workspace::{
        self, Authority, InvestigationAuthority, ManifestArtifactKind, ManifestArtifactPin,
        ManifestAuthority, PassAuthority, TrustedPrincipalSlot, VerifierRuntimeAuthority,
    },
};
use serde_json::json;
use time::OffsetDateTime;

use instrument::{Instrument, SESSIONS};
use supervisor::Supervisor;
pub use supervisor::run_fixture_child_if_requested;

const ENGAGEMENT: &str = "demo";
const PROJECT: &str = "project.teapot.development";
const DECLARATION: &[u8] =
    include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct DemoArgs {
    /// New or unbound directory to use for the tutorial workspace.
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Exact Teapot executable to bind. Defaults to an absolute PATH lookup.
    #[arg(long, value_name = "PATH", conflicts_with = "stop")]
    pub teapot: Option<PathBuf>,
    /// Exact qualified Investigation executable. Defaults to an absolute PATH lookup.
    #[arg(long, value_name = "PATH", conflicts_with = "stop")]
    pub investigation: Option<PathBuf>,
    /// Stop the development fixture and its Teapot engine.
    #[arg(long)]
    pub stop: bool,
}

pub(crate) fn start(context: Context, args: &DemoArgs, state: &Path) -> ResponseV1 {
    let Some(path) = &args.path else {
        return refuse(
            &context,
            ErrorCode::UsageError,
            "Provide a demo workspace path.",
        );
    };
    let Ok(root) = target_path(path) else {
        return refuse(
            &context,
            ErrorCode::UsageError,
            "Use a valid demo workspace directory.",
        );
    };
    if args.stop {
        return stop(context, &root, state);
    }
    if env::var_os("TEAPOT_ENFORCED").is_some() {
        return refuse(
            &context,
            ErrorCode::EnforcementUnavailable,
            "The current Teapot sandbox cannot start a separate demo engine.",
        );
    }
    if root.starts_with(state) || state.starts_with(&root) {
        return refuse(
            &context,
            ErrorCode::WorkspaceUnbound,
            "Choose a demo directory outside Scourge's state directory.",
        );
    }
    if root.exists() && state.join("scourge").exists() {
        match workspace::check_demo_root(&root, state) {
            Ok(mut reservation) => {
                if let Some(response) = resume(&context, &mut reservation) {
                    return response;
                }
            }
            Err(error) => return crate::workspace_failure(&context, error),
        }
    } else if ["scourge.toml", ".scourge"]
        .into_iter()
        .any(|name| root.join(name).symlink_metadata().is_ok())
    {
        return refuse(
            &context,
            ErrorCode::WorkspaceUnbound,
            "Choose an unbound demo directory.",
        );
    }
    let teapot = locate(args.teapot.as_deref(), "teapot", &root)
        .and_then(|path| instrument::qualified_bytes(&path).ok());
    let Some(teapot) = teapot else {
        return refuse(
            &context,
            ErrorCode::DependencyUnavailable,
            "Provide the exact qualified Teapot executable with --teapot PATH.",
        );
    };
    let Some(investigation) = locate(args.investigation.as_deref(), "investigation", &root)
        .and_then(|path| Evidence::qualified_executable_bytes(&path).ok())
    else {
        return refuse(
            &context,
            ErrorCode::DependencyUnavailable,
            "Provide the exact qualified Investigation executable with --investigation PATH.",
        );
    };
    if workspace::create_demo_root(&root)
        .and_then(|()| fs::create_dir_all(state))
        .is_err()
    {
        return refuse(
            &context,
            ErrorCode::DependencyUnavailable,
            "Could not create the demo directories.",
        );
    }
    let mut reservation = match workspace::check_demo_root(&root, state) {
        Ok(value) => value,
        Err(error) => return crate::workspace_failure(&context, error),
    };
    if let Some(response) = resume(&context, &mut reservation) {
        return response;
    }
    if let Err(error) = reservation.check_guide() {
        return SetupFailure::Guide(error).response(&context);
    }
    if let Err(error) = reservation.reset() {
        return startup_failure(
            &context,
            &reservation,
            error.code(),
            "The prior demo setup is still owned or changed. Retry the demo.",
        );
    }
    let home = match reservation.reserve() {
        Ok(value) => value,
        Err(error) => {
            return startup_failure(
                &context,
                &reservation,
                error.code(),
                "Could not reserve the local demo runtime.",
            );
        }
    };
    let Prepared {
        supervisor,
        authority,
    } = match prepare(&home, reservation.root(), state, &teapot, &investigation) {
        Ok(value) => value,
        Err(error) => return error.response(&context),
    };
    if let Err(error) = reservation.prepare(ENGAGEMENT, DECLARATION, authority) {
        return startup_failure(
            &context,
            &reservation,
            error.code(),
            "Could not retain the demo setup receipt.",
        );
    }
    if supervisor.keep().is_err() {
        return startup_failure(
            &context,
            &reservation,
            ErrorCode::DependencyUnavailable,
            "Could not confirm the demo supervisor. Retry the demo.",
        );
    }
    if let Some(response) = resume(&context, &mut reservation) {
        return response;
    }
    startup_failure(
        &context,
        &reservation,
        ErrorCode::DependencyUnavailable,
        "The demo supervisor stopped during startup. Retry the demo.",
    )
}

fn startup_failure(
    context: &Context,
    reservation: &workspace::DemoWorkspace,
    code: ErrorCode,
    message: &'static str,
) -> ResponseV1 {
    let mut context = context.clone();
    let commit = match reservation.confirm_active() {
        Ok(true) => {
            context.workspace = reservation
                .root()
                .to_str()
                .and_then(|path| path.parse().ok());
            context.engagement = ENGAGEMENT.parse().ok();
            CommitStatus::Committed
        }
        Ok(false) => CommitStatus::NotCommitted,
        Err(_) => CommitStatus::Unknown,
    };
    context.failure(code, message, commit, Effect::None)
}

fn resume(context: &Context, reservation: &mut workspace::DemoWorkspace) -> Option<ResponseV1> {
    let authority = reservation.authority()?.clone();
    let control = authority.demo.as_ref().expect("demo receipt");
    if reservation.retired() {
        return Some(startup_failure(
            context,
            reservation,
            ErrorCode::DependencyUnavailable,
            "The demo runtime is retired. Its retained workspace remains readable.",
        ));
    }
    if supervisor::command(control, supervisor::Action::Ping).is_err() {
        return match reservation.active() {
            Ok(false) => None,
            Ok(true) if reservation.retire().is_ok() => Some(startup_failure(
                context,
                reservation,
                ErrorCode::DependencyUnavailable,
                "The demo runtime stopped and was retired. Its retained workspace remains readable.",
            )),
            _ => Some(startup_failure(
                context,
                reservation,
                ErrorCode::DependencyUnavailable,
                "The demo workspace remains committed, but its live fixture could not be confirmed.",
            )),
        };
    }
    let guide = match reservation.publish(ENGAGEMENT) {
        Ok(receipt) => receipt,
        Err(workspace::DemoPublishError::Workspace(error)) => {
            return Some(startup_failure(
                context,
                reservation,
                error.code(),
                "Could not publish the owned demo workspace. Retry the demo.",
            ));
        }
        Err(workspace::DemoPublishError::Guide(error)) => {
            let failure = SetupFailure::Guide(error).response(context);
            let error = failure.error.expect("guide refusal");
            return Some(startup_failure(
                context,
                reservation,
                error.code,
                "Check AGENTS.md before retrying the demo.",
            ));
        }
    };
    if supervisor::command(control, supervisor::Action::Activate).is_err() {
        return Some(startup_failure(
            context,
            reservation,
            ErrorCode::DependencyUnavailable,
            "The demo workspace is committed, but its supervisor did not confirm activation.",
        ));
    }
    let mut context = context.clone();
    context.workspace = reservation
        .root()
        .to_str()
        .and_then(|path| path.parse().ok());
    context.engagement = ENGAGEMENT.parse().ok();
    let origin = &authority.verifier_runtime[ENGAGEMENT].origin;
    Some(ready(context, guide, origin, control.expires))
}

fn ready(
    context: Context,
    guide: workspace::managed_guide::Receipt,
    origin: &TargetOrigin,
    expires: i64,
) -> ResponseV1 {
    let mut response = context.success("demo-ready");
    let stop = Context::default().action(
        ActionEffect::None,
        [
            "demo",
            "--stop",
            "--",
            context.workspace.as_ref().expect("validated path").as_str(),
        ]
        .map(|value| value.parse().expect("valid argv")),
    );
    response.extensions.insert(
        "demo".into(),
        json!({
            "target": origin.as_str(),
            "expires_at": expires,
            "stop_argv": stop.argv,
        }),
    );
    response.extensions.insert(
        "managed_guide".into(),
        crate::managed_guide::receipt_json(guide),
    );
    response.next.push(
        context.action(
            ActionEffect::None,
            [
                "lead",
                "add",
                "bob reads alice's order",
                "--class",
                "web-authz/private-object-read",
                "--property",
                "orders",
                "--slot",
                "other=bob",
            ]
            .map(|value| value.parse().expect("valid argv")),
        ),
    );
    response
}

fn stop(mut context: Context, path: &Path, state: &Path) -> ResponseV1 {
    let cwd = match env::current_dir() {
        Ok(path) => path,
        Err(_) => {
            return refuse(
                &context,
                ErrorCode::DependencyUnavailable,
                "Cannot resolve the demo workspace.",
            );
        }
    };
    let (root, control) = match workspace::select(&cwd, Some(path), state) {
        Ok(bound) => {
            let Some(control) = bound.authority.demo else {
                return refuse(
                    &context,
                    ErrorCode::WorkspaceUnbound,
                    "This workspace has no demo fixture.",
                );
            };
            (bound.root, control)
        }
        Err(error) => match workspace::demo_fallback_control(path, state) {
            Some(fallback) => fallback,
            None => return crate::workspace_failure(&context, error),
        },
    };
    context.workspace = root.to_str().and_then(|path| path.parse().ok());
    context.engagement = ENGAGEMENT.parse().ok();
    match supervisor::command(&control, supervisor::Action::Stop) {
        Ok(()) => context.success("demo-stopped"),
        Err(_) => context.failure(
            ErrorCode::DependencyUnavailable,
            "Could not confirm the demo fixture stopped. Retry the stop command.",
            CommitStatus::Unknown,
            Effect::None,
        ),
    }
}

fn target_path(path: &Path) -> io::Result<PathBuf> {
    let path = workspace::normalize_demo_path(path)?;
    if path
        .to_str()
        .and_then(|path| path.parse::<scourge_core::wire::AbsolutePath>().ok())
        .is_none()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(process::invalid());
    }
    if fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.is_dir()) {
        return Err(process::invalid());
    }
    Ok(path)
}

fn locate(explicit: Option<&Path>, name: &str, root: &Path) -> Option<PathBuf> {
    let check = |path: &Path| {
        let path = fs::canonicalize(path).ok()?;
        let metadata = fs::metadata(&path).ok()?;
        (metadata.is_file()
            && metadata.permissions().mode() & 0o111 != 0
            && !path.starts_with(root))
        .then_some(path)
    };
    if let Some(path) = explicit {
        return check(path);
    }
    env::split_paths(&env::var_os("PATH")?)
        .filter(|dir| dir.is_absolute())
        .find_map(|dir| check(&dir.join(name)))
}

struct Prepared {
    supervisor: Supervisor,
    authority: Authority,
}

fn prepare(
    home: &Path,
    root: &Path,
    state: &Path,
    teapot: &[u8],
    investigation: &[u8],
) -> Result<Prepared, SetupFailure> {
    let evidence_dir = home.join("evidence-root");
    let investigation = provision_investigation(&evidence_dir, investigation)?;
    let evidence = Evidence::initialize_qualified(&investigation).map_err(|error| {
        SetupFailure::Evidence(error, "Could not initialize qualified demo evidence.")
    })?;

    let expires = OffsetDateTime::now_utc() + time::Duration::hours(8);
    let token = uuid::Uuid::new_v4();
    let (mut supervisor, fixture) = Supervisor::start(home, root, state, expires, token)
        .map_err(|_| SetupFailure::Stage("Could not start the owned loopback fixture."))?;
    let instrument = Instrument::new(home, &fixture.runtime);
    instrument
        .stage(teapot)
        .map_err(|_| SetupFailure::Stage("Could not stage the qualified Teapot executable."))?;
    let pass_digest = instrument
        .configure(fixture.address, expires, &fixture.cookies)
        .map_err(|_| SetupFailure::Stage("Could not configure the local Teapot project."))?;
    let origin = TargetOrigin::parse(&format!("http://{}", fixture.address))
        .map_err(|_| process::invalid())?;
    let manifest = EngagementDraft::parse_toml(DECLARATION)
        .and_then(|draft| {
            draft.accept(PassPin {
                reference: &"pass.development-fixture"
                    .parse()
                    .expect("demo pass reference"),
                digest: &pass_digest,
            })
        })
        .map_err(|_| process::invalid())?;
    let retained = retain_manifest(&evidence, &manifest)?;
    let pid = supervisor
        .start_engine()
        .map_err(|_| SetupFailure::Stage("Could not start the owned Teapot engine."))?;
    let engine = instrument
        .ready(pid)
        .map_err(|_| SetupFailure::Stage("Could not confirm the owned Teapot engine was ready."))?;
    let runtime = runtime(
        retained,
        investigation,
        &instrument,
        engine,
        origin.clone(),
        pass_digest,
        &manifest,
    );
    let adapter = Teapot::from_runtime(&runtime).map_err(|_| process::invalid())?;
    let sessions = SESSIONS.map(|session| session.parse().expect("demo session name"));
    adapter
        .verifier_preflight(&sessions, RequiredEnforcement::None)
        .map_err(|error| SetupFailure::Native(error.code()))?;
    fs::File::open(home)?.sync_all()?;
    fs::File::open(state.join("scourge"))?.sync_all()?;
    let authority = Authority {
        teapot_projects: [(PROJECT.to_owned(), instrument.paths)].into(),
        verifier_runtime: [(ENGAGEMENT.to_owned(), runtime)].into(),
        demo: Some(workspace::DemoControl {
            socket: fixture.runtime.join("stop.sock"),
            expires: expires.unix_timestamp(),
            token,
        }),
        ..Authority::default()
    };
    Ok(Prepared {
        supervisor,
        authority,
    })
}

fn provision_investigation(root: &Path, binary: &[u8]) -> io::Result<InvestigationAuthority> {
    let executable = root.join("investigation");
    let authority = InvestigationAuthority {
        executable,
        case_root: root.to_owned(),
        workspace_root: root.join("workspace"),
        import_root: root.join("import"),
        scratch_root: root.join("scratch"),
    };
    for path in [
        root,
        &authority.workspace_root,
        &authority.import_root,
        &authority.scratch_root,
    ] {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let mut executable = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&authority.executable)?;
    executable.write_all(binary)?;
    executable.sync_all()?;
    Ok(authority)
}

fn retain_manifest(
    evidence: &Evidence,
    manifest: &ManifestRevision,
) -> Result<ManifestArtifactPin, SetupFailure> {
    let capture = evidence.capture(&RunId::generate()).map_err(|error| {
        SetupFailure::Evidence(error, "Could not open the demo manifest capture.")
    })?;
    evidence
        .attach(&capture, 1, "engagement", manifest.canonical_bytes())
        .map_err(|error| SetupFailure::Evidence(error, "Could not attach the demo manifest."))?;
    let completed = evidence
        .finalize(&capture, Some(1), Completion::Complete, &["engagement"])
        .map_err(|error| SetupFailure::Evidence(error, "Could not seal the demo manifest."))?;
    let [original] = completed.original_artifacts.as_slice() else {
        return Err(process::invalid().into());
    };
    let retained = evidence
        .read_json(&original.artifact.artifact_id)
        .map_err(|error| {
            SetupFailure::Evidence(error, "Could not read back the sealed demo manifest.")
        })?
        .artifact;
    if retained.reference.digest != *manifest.digest() {
        return Err(process::invalid().into());
    }
    Ok(ManifestArtifactPin {
        kind: ManifestArtifactKind::EngagementManifest,
        reference: retained.reference,
        revision: retained.revision,
        size_bytes: retained.size_bytes,
        source_id: retained.source_id.parse().map_err(|_| process::invalid())?,
    })
}

fn runtime(
    artifact: ManifestArtifactPin,
    investigation: InvestigationAuthority,
    instrument: &Instrument,
    engine: BoundEngine,
    origin: TargetOrigin,
    pass_digest: scourge_core::canonical::Sha256Digest,
    manifest: &ManifestRevision,
) -> VerifierRuntimeAuthority {
    VerifierRuntimeAuthority {
        manifest: ManifestAuthority {
            revision: manifest.revision(),
            digest: manifest.digest().clone(),
            canonical_bytes: manifest.canonical_bytes().to_vec(),
            artifact,
        },
        pass: PassAuthority {
            path: instrument.pass.clone(),
            digest: pass_digest,
        },
        teapot: instrument.paths.clone(),
        engine,
        investigation,
        target: manifest.target_version().clone(),
        origin,
        environment_kind: EnvironmentKind::Simulated,
        custody: Custody::Shared,
        target_isolation: TargetIsolation::SeparatePrincipalsUnconfined,
        principal_slots: [(
            "owner".parse().expect("demo owner slot"),
            TrustedPrincipalSlot {
                principal: "alice".parse().expect("demo owner"),
                provenance: "scourge-demo".parse().expect("demo owner provenance"),
            },
        )]
        .into(),
    }
}

enum SetupFailure {
    Io,
    Stage(&'static str),
    Evidence(EvidenceError, &'static str),
    Native(ErrorCode),
    Guide(workspace::managed_guide::Error),
}

impl From<io::Error> for SetupFailure {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

impl SetupFailure {
    fn response(self, context: &Context) -> ResponseV1 {
        match self {
            Self::Io => refuse(
                context,
                ErrorCode::DependencyUnavailable,
                "Could not prepare the local demo runtime.",
            ),
            Self::Stage(message) => refuse(context, ErrorCode::DependencyUnavailable, message),
            Self::Evidence(error, message) => refuse(context, error.code(), message),
            Self::Native(code) => refuse(
                context,
                code,
                "The owned Teapot engine did not pass the verifier readiness checks.",
            ),
            Self::Guide(error) => {
                use workspace::managed_guide::Error;
                let code = match error {
                    Error::Ambiguous | Error::Edited | Error::UnsafePath => {
                        ErrorCode::IntegrityFailure
                    }
                    Error::Busy => ErrorCode::ConflictingRun,
                    Error::Io(_) => ErrorCode::DependencyUnavailable,
                };
                refuse(context, code, "Check AGENTS.md before starting the demo.")
            }
        }
    }
}

fn refuse(context: &Context, code: ErrorCode, message: &'static str) -> ResponseV1 {
    let mut response = context.failure(code, message, CommitStatus::NotCommitted, Effect::None);
    response.next.push(context.action(
        ActionEffect::None,
        ["demo", "--help"].map(|value| value.parse().expect("valid argv")),
    ));
    response
}
