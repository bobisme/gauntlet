//! Workspace discovery is selection only. Authority is read solely from the
//! operator-owned state directory, never from a selected tree.
use crate::{
    canonical::Sha256Digest,
    engagement::EngagementDraft,
    evidence::{Artifact as RetainedArtifact, Evidence, EvidenceError},
    ids::EngagementId,
    wire::ErrorCode,
};
use rustix::fs::{self as rfs, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

mod coordination;
pub mod managed_guide;

const LIMIT: u64 = 1_048_576;
const CONFIG: &str = "scourge.toml";

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("workspace is missing or not bound; run scourge init")]
    Unbound,
    #[error("choose an engagement explicitly")]
    EngagementRequired,
    #[error("engagement not found")]
    EngagementNotFound,
    #[error("invalid engagement declaration")]
    InvalidEngagement,
    #[error("the bound coordination store is not provisioned")]
    CoordinationUnavailable,
    #[error("the bound coordination path is invalid")]
    CoordinationInvalid,
    #[error("the bound coordination database could not be opened")]
    Coordination(#[from] crate::store::StoreError),
    #[error("workspace setup failed")]
    Io(#[from] std::io::Error),
}
impl WorkspaceError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Unbound => ErrorCode::WorkspaceUnbound,
            Self::EngagementRequired => ErrorCode::EngagementRequired,
            Self::EngagementNotFound => ErrorCode::ObjectNotFound,
            Self::InvalidEngagement => ErrorCode::SchemaInvalid,
            Self::CoordinationUnavailable => ErrorCode::CapabilityUnavailable,
            Self::CoordinationInvalid => ErrorCode::IntegrityFailure,
            Self::Coordination(error) => error.error_code(),
            Self::Io(_) => ErrorCode::DependencyUnavailable,
        }
    }
}

/// Explicit operator-provided locators. Empty means no authority configured.
/// These values are never derived from workspace configuration or engagement files.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub executables: BTreeMap<String, PathBuf>,
    pub evidence_root: Option<PathBuf>,
    pub credential_sources: BTreeMap<String, String>,
    pub sockets: BTreeMap<String, PathBuf>,
    /// Passive project-store bindings keyed by the engagement's declared
    /// instrument project reference. These paths are operator authority; they
    /// are never inferred from a selected workspace tree.
    #[serde(default)]
    pub teapot_projects: BTreeMap<String, TeapotProjectAuthority>,
    /// Complete operator-owned verifier bindings keyed by engagement name.
    #[serde(default)]
    pub verifier_runtime: BTreeMap<String, VerifierRuntimeAuthority>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TeapotProjectAuthority {
    pub executable: PathBuf,
    pub project: PathBuf,
    pub home: PathBuf,
    pub config_home: Option<PathBuf>,
    pub data_home: Option<PathBuf>,
    pub state_home: Option<PathBuf>,
    pub cache_home: Option<PathBuf>,
    pub runtime_dir: Option<PathBuf>,
    #[serde(default)]
    pub wrapper: bool,
}

/// Complete inert verifier configuration. Validation never opens these paths.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifierRuntimeAuthority {
    pub manifest: ManifestAuthority,
    pub pass: PassAuthority,
    pub teapot: TeapotProjectAuthority,
    pub engine: crate::teapot::BoundEngine,
    pub investigation: InvestigationAuthority,
    pub target: crate::engagement::VersionRef,
    pub origin: crate::rounds::TargetOrigin,
    /// Operator-admitted environment classification for verification records.
    pub environment_kind: crate::wire::EnvironmentKind,
    /// Custody actually provided by this runtime. The current in-process
    /// adapter admits only shared custody.
    pub custody: crate::wire::Custody,
    /// Target-account isolation established independently of runtime identity.
    pub target_isolation: crate::wire::TargetIsolation,
    pub principal_slots: BTreeMap<crate::template::SlotName, TrustedPrincipalSlot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestAuthority {
    pub revision: u64,
    pub digest: Sha256Digest,
    pub canonical_bytes: Vec<u8>,
    /// Independent retained Evidence artifact identity and metadata.
    pub artifact: ManifestArtifactPin,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestArtifactPin {
    pub kind: ManifestArtifactKind,
    pub reference: crate::wire::Artifact,
    pub revision: u64,
    pub size_bytes: usize,
    pub source_id: crate::ids::WireText,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManifestArtifactKind {
    EngagementManifest,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PassAuthority {
    pub path: PathBuf,
    pub digest: Sha256Digest,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InvestigationAuthority {
    pub executable: PathBuf,
    /// Operator-owned directory containing the canonical Investigation workspace.
    pub case_root: PathBuf,
    pub workspace_root: PathBuf,
    pub import_root: PathBuf,
    /// Operator-owned mode-0700 parent for private bridge staging.
    pub scratch_root: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedPrincipalSlot {
    pub principal: crate::engagement::Label,
    /// Operator identity or local source responsible for this override.
    pub provenance: crate::ids::WireText,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeAuthorityError {
    #[error("verifier runtime authority is missing")]
    Missing,
    #[error("verifier runtime authority conflicts with the selected engagement")]
    Conflict,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifierEvidenceError {
    #[error(transparent)]
    Authority(#[from] RuntimeAuthorityError),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
}

/// The qualified case and the exact manifest/pass pin admitted by the operator.
pub struct VerifierEvidence<'a> {
    evidence: Evidence,
    engagement: EngagementId,
    runtime: &'a VerifierRuntimeAuthority,
}

impl VerifierEvidence<'_> {
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn engagement(&self) -> &EngagementId {
        &self.engagement
    }

    pub fn manifest(&self) -> &ManifestAuthority {
        &self.runtime.manifest
    }

    pub fn pass_digest(&self) -> &Sha256Digest {
        &self.runtime.pass.digest
    }

    /// Recheck retention and metadata inside a named evidence snapshot.
    pub fn check_manifest(&self) -> Result<(), EvidenceError> {
        let manifest = self.manifest();
        let pin = &manifest.artifact;
        let read = self
            .evidence
            .read_checked(&pin.reference.artifact_id, |artifact| pin.check(artifact))?;
        // Runtime resolution verified the canonical byte sequence and bound
        // its manifest revision and pass digest to the operator's pins.
        if read.bytes != manifest.canonical_bytes {
            return Err(EvidenceError::Integrity);
        }
        Ok(())
    }
}

impl ManifestArtifactPin {
    fn check(&self, retained: &RetainedArtifact) -> Result<(), EvidenceError> {
        if retained.reference != self.reference
            || retained.revision != self.revision
            || retained.size_bytes != self.size_bytes
            || retained.source_id != self.source_id.as_str()
        {
            return Err(EvidenceError::Integrity);
        }
        Ok(())
    }
}

fn retry_manifest_check(
    mut check: impl FnMut() -> Result<(), EvidenceError>,
) -> Result<(), EvidenceError> {
    for _ in 1..3 {
        match check() {
            Err(EvidenceError::ChangedSnapshot) => continue,
            result => return result,
        }
    }
    check()
}

fn valid_runtime(binding: &VerifierRuntimeAuthority) -> bool {
    let artifact = &binding.manifest.artifact;
    let paths = [
        &binding.pass.path,
        &binding.investigation.executable,
        &binding.investigation.case_root,
        &binding.investigation.workspace_root,
        &binding.investigation.import_root,
        &binding.investigation.scratch_root,
        &binding.teapot.executable,
        &binding.teapot.project,
        &binding.teapot.home,
    ];
    paths
        .into_iter()
        .chain(binding.teapot.config_home.iter())
        .chain(binding.teapot.data_home.iter())
        .chain(binding.teapot.state_home.iter())
        .chain(binding.teapot.cache_home.iter())
        .chain(binding.teapot.runtime_dir.iter())
        .all(|path| {
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        })
        && artifact.kind == ManifestArtifactKind::EngagementManifest
        && crate::evidence::full_id(artifact.reference.artifact_id.as_str(), "art_")
        && crate::evidence::full_id(artifact.source_id.as_str(), "src_")
        && artifact.revision > 0
        && artifact.size_bytes == binding.manifest.canonical_bytes.len()
        && artifact.reference.digest == binding.manifest.digest
        && crate::engagement::ManifestRevision::from_canonical_bytes(
            &binding.manifest.canonical_bytes,
            &binding.manifest.digest,
        )
        .is_ok_and(|m| {
            m.revision() == binding.manifest.revision
                && m.pass_digest() == &binding.pass.digest
                && m.target_version() == &binding.target
        })
        && binding.custody == crate::wire::Custody::Shared
        && binding.target_isolation == crate::wire::TargetIsolation::SeparatePrincipalsUnconfined
        && binding.principal_slots.iter().all(|(slot, value)| {
            matches!(slot.as_str(), "owner" | "other") && !value.provenance.as_str().is_empty()
        })
        && {
            let mut principals = std::collections::HashSet::new();
            binding
                .principal_slots
                .values()
                .all(|v| principals.insert(&v.principal))
        }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(Clone)]
struct Config {
    version: u8,
    workspace_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(Clone)]
struct Binding {
    version: u8,
    workspace_id: String,
    root: PathBuf,
    config_digest: String,
    authority: Authority,
    engagements: BTreeMap<String, Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    config: Vec<u8>,
    binding: Binding,
}

fn valid_authority(a: &Authority) -> bool {
    let ordinary = a
        .executables
        .values()
        .chain(a.evidence_root.iter())
        .chain(a.sockets.values())
        .all(|path| {
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        });
    let teapot = a.teapot_projects.values().all(|binding| {
        std::iter::once(&binding.executable)
            .chain(std::iter::once(&binding.project))
            .chain(std::iter::once(&binding.home))
            .chain(binding.config_home.iter())
            .chain(binding.data_home.iter())
            .chain(binding.state_home.iter())
            .chain(binding.cache_home.iter())
            .chain(binding.runtime_dir.iter())
            .all(|path| {
                path.is_absolute()
                    && !path.components().any(|component| {
                        matches!(component, Component::ParentDir | Component::CurDir)
                    })
            })
    });
    ordinary
        && teapot
        && a.verifier_runtime
            .iter()
            .all(|(name, binding)| valid_name(name) && valid_runtime(binding))
}

/// A validated binding. Merely discovering a configuration never returns one.
pub struct BoundWorkspace {
    pub root: PathBuf,
    pub authority: Authority,
    workspace_id: String,
    engagements: BTreeMap<String, Vec<u8>>,
}
impl BoundWorkspace {
    /// Resolve trusted runtime configuration without opening adapters, files or sockets.
    pub fn resolve_verifier_runtime(
        &self,
        engagement: &str,
    ) -> Result<&VerifierRuntimeAuthority, RuntimeAuthorityError> {
        let declaration = self
            .engagements
            .get(engagement)
            .ok_or(RuntimeAuthorityError::Conflict)?;
        let binding = self
            .authority
            .verifier_runtime
            .get(engagement)
            .ok_or(RuntimeAuthorityError::Missing)?;
        if !valid_runtime(binding) {
            return Err(RuntimeAuthorityError::Conflict);
        }
        let manifest = crate::engagement::ManifestRevision::from_canonical_bytes(
            &binding.manifest.canonical_bytes,
            &binding.manifest.digest,
        )
        .map_err(|_| RuntimeAuthorityError::Conflict)?;
        if manifest.source_digest() != &Sha256Digest::of(declaration)
            || self
                .authority
                .teapot_projects
                .get(manifest.settings().instrument.project.as_str())
                .is_some_and(|passive| passive != &binding.teapot)
            || binding
                .principal_slots
                .values()
                .any(|slot| !manifest.principals().contains_key(&slot.principal))
        {
            return Err(RuntimeAuthorityError::Conflict);
        }
        let mut sessions = std::collections::HashSet::new();
        if binding
            .principal_slots
            .values()
            .any(|slot| !sessions.insert(&manifest.principals()[&slot.principal].session))
        {
            return Err(RuntimeAuthorityError::Conflict);
        }
        Ok(binding)
    }

    /// Reopen the qualified case and validate the retained manifest against the
    /// accepted operator binding. Archived reads do not consult the pass file.
    pub fn open_verifier_evidence(
        &self,
        engagement: &EngagementId,
    ) -> Result<VerifierEvidence<'_>, VerifierEvidenceError> {
        let runtime = self.resolve_verifier_runtime(engagement.as_str())?;
        let evidence = Evidence::open_qualified(&runtime.investigation)?;
        let qualified = VerifierEvidence {
            evidence,
            engagement: engagement.clone(),
            runtime,
        };
        retry_manifest_check(|| qualified.check_manifest())?;
        Ok(qualified)
    }

    /// Open only this workspace's existing local coordination database.
    /// This never initializes, migrates, or reads authority from the tree.
    pub fn open_coordination(&self) -> Result<crate::store::read::ReadStore, WorkspaceError> {
        coordination::open(&self.root, &self.workspace_id)
    }

    /// Open this workspace's already-provisioned coordination database for an
    /// authorized local mutation. The pathname and workspace identity are
    /// rechecked before and after opening just like the read path.
    pub fn open_coordination_writer(&self) -> Result<crate::store::Store, WorkspaceError> {
        coordination::open_write(&self.root, &self.workspace_id)
    }

    /// Scope request keys to this binding's private workspace identity and a
    /// registered engagement, independently of how the workspace was selected.
    pub fn request_scope(
        &self,
        engagement: &crate::ids::EngagementId,
    ) -> Result<crate::store::RequestScope, WorkspaceError> {
        self.select_engagement(Some(engagement.as_str()))?;
        let binding = format!("workspace:{}", self.workspace_id)
            .parse()
            .map_err(|_| WorkspaceError::CoordinationInvalid)?;
        Ok(crate::store::RequestScope::new(engagement.clone(), binding))
    }

    pub fn engagements(&self) -> impl Iterator<Item = &str> {
        self.engagements.keys().map(String::as_str)
    }
    pub fn select_engagement(&self, name: Option<&str>) -> Result<(&str, &[u8]), WorkspaceError> {
        let (key, value) = match name {
            Some(name) => self
                .engagements
                .get_key_value(name)
                .ok_or(WorkspaceError::EngagementNotFound)?,
            None if self.engagements.len() == 1 => self
                .engagements
                .iter()
                .next()
                .ok_or(WorkspaceError::EngagementRequired)?,
            None => return Err(WorkspaceError::EngagementRequired),
        };
        Ok((key, value))
    }
}

fn valid_engagement(bytes: &[u8]) -> bool {
    let draft = if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(123) {
        EngagementDraft::parse_json(bytes)
    } else {
        EngagementDraft::parse_toml(bytes)
    };
    draft.and_then(|d| d.validate()).is_ok()
}
fn valid_name(name: &str) -> bool {
    name.parse::<crate::ids::EngagementId>().is_ok()
}
fn read_limited(mut f: File) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut f).take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(std::io::Error::other("file too large"));
    }
    Ok(bytes)
}
fn nofollow_file(dir: &File, name: &str) -> std::io::Result<File> {
    Ok(File::from(rfs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?))
}
fn open_dir(path: &Path) -> std::io::Result<File> {
    if !path.is_absolute() {
        return Err(std::io::Error::other("absolute path required"));
    }
    let mut dir = File::open("/")?;
    for part in path.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => {
                dir = File::from(rfs::openat(
                    &dir,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?)
            }
            _ => return Err(std::io::Error::other("invalid path component")),
        }
    }
    Ok(dir)
}
fn state_dir_with<F>(state: &Path, create: bool, hook: &mut F) -> std::io::Result<File>
where
    F: FnMut(&str) -> std::io::Result<()>,
{
    let parent = open_dir(state)?;
    if create {
        match rfs::mkdirat(&parent, "scourge", Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {
                hook("state_parent_flush")?;
                rfs::fsync(&parent)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let dir = File::from(rfs::openat(
        &parent,
        "scourge",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let stat = rfs::fstat(&dir)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err(std::io::Error::other(
            "unsafe state directory ownership or permissions",
        ));
    }
    Ok(dir)
}
#[cfg(test)]
fn state_dir(state: &Path, create: bool) -> std::io::Result<File> {
    state_dir_with(state, create, &mut |_| Ok(()))
}
fn key(root: &Path, config: &[u8]) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut material = root.as_os_str().as_bytes().to_vec();
    material.push(0);
    material.extend_from_slice(config);
    Sha256Digest::of(&material).as_str().to_owned()
}
fn atomic_write_with<F>(
    dir: &File,
    name: &str,
    bytes: &[u8],
    exclusive: bool,
    stage: &str,
    hook: &mut F,
) -> std::io::Result<()>
where
    F: FnMut(&str) -> std::io::Result<()>,
{
    let temp = format!(".{}.tmp", Uuid::new_v4());
    let fd = rfs::openat(
        dir,
        temp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let mut file = File::from(fd);
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        if exclusive {
            rfs::renameat_with(dir, temp.as_str(), dir, name, rfs::RenameFlags::NOREPLACE)?;
        } else {
            rfs::renameat(dir, temp.as_str(), dir, name)?;
        }
        hook(stage)?;
        rfs::fsync(dir)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = rfs::unlinkat(dir, temp.as_str(), rfs::AtFlags::empty());
    }
    result
}
#[cfg(test)]
fn atomic_write(dir: &File, name: &str, bytes: &[u8], exclusive: bool) -> std::io::Result<()> {
    atomic_write_with(dir, name, bytes, exclusive, "flush", &mut |_| Ok(()))
}
// A pending record is operator-owned and survives a crash. It fixes the identity
// and exact input before either public config or final binding is published.
fn pending_key(root: &Path) -> String {
    format!("pending-{}", key(root, b"init-v1"))
}
fn read_private(dir: &File, name: &str) -> std::io::Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let file = nofollow_file(dir, name)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err(std::io::Error::other("unsafe private file"));
    }
    read_limited(file)
}
fn contains_dir(ancestor: &File, descendant: &File) -> std::io::Result<bool> {
    let target = rfs::fstat(ancestor)?;
    let mut current = descendant.try_clone()?;
    loop {
        let stat = rfs::fstat(&current)?;
        if stat.st_dev == target.st_dev && stat.st_ino == target.st_ino {
            return Ok(true);
        }
        let parent = File::from(rfs::openat(
            &current,
            "..",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let upper = rfs::fstat(&parent)?;
        if stat.st_dev == upper.st_dev && stat.st_ino == upper.st_ino {
            return Ok(false);
        }
        current = parent;
    }
}
// Compare opened identities, and retain those exact handles for all accesses.
fn independent_state(root: &File, state: &File) -> Result<(), WorkspaceError> {
    if contains_dir(root, state)? || contains_dir(state, root)? {
        return Err(WorkspaceError::Unbound);
    }
    Ok(())
}
fn config_bytes(config: &Config) -> std::io::Result<Vec<u8>> {
    Ok(toml::to_string(config)
        .map_err(|_| std::io::Error::other("config serialization"))?
        .into_bytes())
}
fn publish_same<F>(
    dir: &File,
    name: &str,
    bytes: &[u8],
    private: bool,
    stage: &str,
    hook: &mut F,
) -> Result<(), WorkspaceError>
where
    F: FnMut(&str) -> std::io::Result<()>,
{
    match atomic_write_with(dir, name, bytes, true, stage, hook) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = if private {
                read_private(dir, name).map_err(|_| WorkspaceError::Unbound)?
            } else {
                let file = nofollow_file(dir, name).map_err(|_| WorkspaceError::Unbound)?;
                if !file
                    .metadata()
                    .map_err(|_| WorkspaceError::Unbound)?
                    .is_file()
                {
                    return Err(WorkspaceError::Unbound);
                }
                read_limited(file).map_err(|_| WorkspaceError::Unbound)?
            };
            if existing != bytes {
                return Err(WorkspaceError::Unbound);
            }
            hook(stage)?;
            rfs::fsync(dir).map_err(std::io::Error::from)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}
/// Create a workspace and binding. An identical retry completes an interrupted
/// init using a private durable intent. Existing unrelated files are not replaced.
pub fn init(
    root: &Path,
    state: &Path,
    name: &str,
    declaration: &[u8],
    authority: Authority,
) -> Result<BoundWorkspace, WorkspaceError> {
    init_with_hook(root, state, name, declaration, authority, |_| Ok(())).map(|(bound, _)| bound)
}

fn init_with_hook<F>(
    root: &Path,
    state: &Path,
    name: &str,
    declaration: &[u8],
    authority: Authority,
    mut hook: F,
) -> Result<(BoundWorkspace, File), WorkspaceError>
where
    F: FnMut(&str) -> std::io::Result<()>,
{
    if !valid_name(name) || !valid_engagement(declaration) {
        return Err(WorkspaceError::InvalidEngagement);
    }
    if !valid_authority(&authority) {
        return Err(WorkspaceError::Unbound);
    }
    fs::create_dir_all(root)?;
    let root = fs::canonicalize(root)?;
    let root_dir = open_dir(&root)?;
    let sd = state_dir_with(state, true, &mut hook)?;
    independent_state(&root_dir, &sd)?;
    hook("directories_checked")?;
    independent_state(&root_dir, &sd)?;
    let pending_name = pending_key(&root);
    let mut engagements = BTreeMap::new();
    engagements.insert(name.to_owned(), declaration.to_vec());
    let config = Config {
        version: 1,
        workspace_id: Uuid::new_v4().to_string(),
    };
    let bytes = config_bytes(&config)?;
    let binding = Binding {
        version: 1,
        workspace_id: config.workspace_id,
        root: root.clone(),
        config_digest: Sha256Digest::of(&bytes).as_str().to_owned(),
        authority: authority.clone(),
        engagements: engagements.clone(),
    };
    let proposed = Pending {
        config: bytes,
        binding,
    };
    let encoded = serde_json::to_vec(&proposed).map_err(std::io::Error::other)?;
    let final_encoded = serde_json::to_vec(&proposed.binding).map_err(std::io::Error::other)?;
    if encoded.len() as u64 > LIMIT || final_encoded.len() as u64 > LIMIT {
        return Err(WorkspaceError::InvalidEngagement);
    }
    // An existing config is never adopted without an already published intent.
    match nofollow_file(&root_dir, CONFIG) {
        Ok(_) => {
            read_private(&sd, &pending_name).map_err(|_| WorkspaceError::Unbound)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(WorkspaceError::Unbound),
    }
    match atomic_write_with(
        &sd,
        &pending_name,
        &encoded,
        true,
        "intent_flush",
        &mut hook,
    ) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            hook("intent_flush")?;
            rfs::fsync(&sd).map_err(std::io::Error::from)?;
        }
        Err(e) => return Err(e.into()),
    }
    hook("intent")?;
    let pending: Pending = crate::wire::from_slice(
        &read_private(&sd, &pending_name).map_err(|_| WorkspaceError::Unbound)?,
    )
    .map_err(|_| WorkspaceError::Unbound)?;
    let cfg: Config =
        toml::from_str(std::str::from_utf8(&pending.config).map_err(|_| WorkspaceError::Unbound)?)
            .map_err(|_| WorkspaceError::Unbound)?;
    let b = &pending.binding;
    if cfg.version != 1
        || Uuid::parse_str(&cfg.workspace_id).is_err()
        || cfg.workspace_id != b.workspace_id
        || b.version != 1
        || b.root != root
        || b.config_digest != Sha256Digest::of(&pending.config).as_str()
        || b.authority != authority
        || b.engagements != engagements
    {
        return Err(WorkspaceError::Unbound);
    }
    let serialized = serde_json::to_vec(b).map_err(std::io::Error::other)?;
    if serialized.len() as u64 > LIMIT {
        return Err(WorkspaceError::InvalidEngagement);
    }
    coordination::provision(
        &root,
        &root_dir,
        &b.workspace_id,
        b.engagements.keys(),
        &mut hook,
    )?;
    publish_same(
        &sd,
        &key(&root, &pending.config),
        &serialized,
        true,
        "binding_flush",
        &mut hook,
    )?;
    hook("binding")?;
    publish_same(
        &root_dir,
        CONFIG,
        &pending.config,
        false,
        "config_flush",
        &mut hook,
    )?;
    hook("config")?;
    Ok((
        BoundWorkspace {
            root,
            authority,
            workspace_id: b.workspace_id.clone(),
            engagements,
        },
        root_dir,
    ))
}
fn discover_with<F>(start: &Path, mut lookup: F) -> Result<PathBuf, WorkspaceError>
where
    F: FnMut(&Path) -> std::io::Result<()>,
{
    for path in start.ancestors() {
        match lookup(path) {
            Ok(()) => return Ok(path.to_path_buf()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(WorkspaceError::Unbound),
        }
    }
    Err(WorkspaceError::Unbound)
}
/// Resolve explicit root or nearest configuration, then validate the independent
/// operator binding. No adapter, credential, socket or evidence access occurs.
pub fn select(
    start: &Path,
    explicit: Option<&Path>,
    state: &Path,
) -> Result<BoundWorkspace, WorkspaceError> {
    select_with_hook(start, explicit, state, || Ok(()))
}
fn select_with_hook<F>(
    start: &Path,
    explicit: Option<&Path>,
    state: &Path,
    mut hook: F,
) -> Result<BoundWorkspace, WorkspaceError>
where
    F: FnMut() -> std::io::Result<()>,
{
    let root = if let Some(root) = explicit {
        fs::canonicalize(root).map_err(|_| WorkspaceError::Unbound)?
    } else {
        let start = fs::canonicalize(start).map_err(|_| WorkspaceError::Unbound)?;
        discover_with(&start, |path| {
            path.join(CONFIG).symlink_metadata().map(|_| ())
        })?
    };
    let dir = open_dir(&root).map_err(|_| WorkspaceError::Unbound)?;
    let sd = state_dir_with(state, false, &mut |_| Ok(())).map_err(|_| WorkspaceError::Unbound)?;
    independent_state(&dir, &sd).map_err(|_| WorkspaceError::Unbound)?;
    hook().map_err(|_| WorkspaceError::Unbound)?;
    independent_state(&dir, &sd).map_err(|_| WorkspaceError::Unbound)?;
    let (binding, _) = read_binding(&root, &dir, &sd)?;
    Ok(BoundWorkspace {
        root,
        authority: binding.authority,
        workspace_id: binding.workspace_id,
        engagements: binding.engagements,
    })
}
fn read_binding(root: &Path, dir: &File, sd: &File) -> Result<(Binding, String), WorkspaceError> {
    let config_file = nofollow_file(dir, CONFIG).map_err(|_| WorkspaceError::Unbound)?;
    if !config_file
        .metadata()
        .map_err(|_| WorkspaceError::Unbound)?
        .is_file()
    {
        return Err(WorkspaceError::Unbound);
    }
    let bytes = read_limited(config_file).map_err(|_| WorkspaceError::Unbound)?;
    let config: Config =
        toml::from_str(std::str::from_utf8(&bytes).map_err(|_| WorkspaceError::Unbound)?)
            .map_err(|_| WorkspaceError::Unbound)?;
    if config.version != 1 || Uuid::parse_str(&config.workspace_id).is_err() {
        return Err(WorkspaceError::Unbound);
    }
    let binding_key = key(root, &bytes);
    let file = nofollow_file(sd, &binding_key).map_err(|_| WorkspaceError::Unbound)?;
    let metadata = file.metadata().map_err(|_| WorkspaceError::Unbound)?;
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(WorkspaceError::Unbound);
    }
    let binding: Binding =
        crate::wire::from_slice(&read_limited(file).map_err(|_| WorkspaceError::Unbound)?)
            .map_err(|_| WorkspaceError::Unbound)?;
    if binding.version != 1
        || binding.workspace_id != config.workspace_id
        || binding.root != root
        || binding.config_digest != Sha256Digest::of(&bytes).as_str()
        || !valid_authority(&binding.authority)
        || binding.engagements.is_empty()
        || binding
            .engagements
            .iter()
            .any(|(name, value)| !valid_name(name) || !valid_engagement(value))
    {
        return Err(WorkspaceError::Unbound);
    }
    Ok((binding, binding_key))
}

/// Add an explicitly named, validated engagement without changing authority.
/// Concurrent additions serialize on the operator-state lock.
pub fn add_engagement(
    start: &Path,
    explicit: Option<&Path>,
    state: &Path,
    name: &str,
    declaration: &[u8],
) -> Result<BoundWorkspace, WorkspaceError> {
    add_engagement_with_hook(start, explicit, state, name, declaration, |_| Ok(()))
}
fn add_engagement_with_hook<F>(
    start: &Path,
    explicit: Option<&Path>,
    state: &Path,
    name: &str,
    declaration: &[u8],
    mut hook: F,
) -> Result<BoundWorkspace, WorkspaceError>
where
    F: FnMut(&str) -> std::io::Result<()>,
{
    if !valid_name(name) || !valid_engagement(declaration) {
        return Err(WorkspaceError::InvalidEngagement);
    }
    let selected = select(start, explicit, state)?;
    let root = selected.root;
    let dir = open_dir(&root).map_err(|_| WorkspaceError::Unbound)?;
    let sd = state_dir_with(state, false, &mut |_| Ok(())).map_err(|_| WorkspaceError::Unbound)?;
    independent_state(&dir, &sd)?;
    let lock = File::from(
        rfs::openat(
            &sd,
            "engagement.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(std::io::Error::from)?,
    );
    use std::os::unix::fs::MetadataExt;
    let meta = lock.metadata()?;
    if !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err(WorkspaceError::Unbound);
    }
    rfs::flock(&lock, rfs::FlockOperation::LockExclusive).map_err(std::io::Error::from)?;
    independent_state(&dir, &sd)?;
    let (mut binding, binding_key) = read_binding(&root, &dir, &sd)?;
    if let Some(old) = binding.engagements.get(name) {
        if old != declaration {
            return Err(WorkspaceError::Unbound);
        }
        coordination::provision(
            &root,
            &dir,
            &binding.workspace_id,
            binding.engagements.keys(),
            &mut hook,
        )?;
        hook("binding_flush")?;
        rfs::fsync(&sd).map_err(std::io::Error::from)?;
    } else {
        binding
            .engagements
            .insert(name.to_owned(), declaration.to_vec());
        let encoded = serde_json::to_vec(&binding).map_err(std::io::Error::other)?;
        if encoded.len() as u64 > LIMIT {
            return Err(WorkspaceError::InvalidEngagement);
        }
        // The new row is unavailable to readers until the binding publishes
        // its name. An interrupted publish can be retried without replacing
        // existing coordination state.
        coordination::provision(
            &root,
            &dir,
            &binding.workspace_id,
            binding.engagements.keys(),
            &mut hook,
        )?;
        atomic_write_with(
            &sd,
            &binding_key,
            &encoded,
            false,
            "binding_flush",
            &mut hook,
        )?;
    }
    Ok(BoundWorkspace {
        root,
        authority: binding.authority,
        workspace_id: binding.workspace_id,
        engagements: binding.engagements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    const ENGAGEMENT: &[u8] =
        include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");
    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("workspace");
        let state = tmp.path().join("state");
        fs::create_dir(&state).unwrap();
        (tmp, root, state)
    }
    fn binding_file(root: &Path, state: &Path) -> PathBuf {
        let config = fs::read(root.join(CONFIG)).unwrap();
        state.join("scourge").join(key(root, &config))
    }
    #[test]
    fn init_select_and_invalid_binding() {
        let (_tmp, root, state) = setup();
        init(&root, &state, "first", ENGAGEMENT, Authority::default()).unwrap();
        let nested = root.join("nested");
        fs::create_dir(&nested).unwrap();
        let bound = select(&nested, None, &state).unwrap();
        assert_eq!(bound.root, root);
        assert_eq!(bound.select_engagement(None).unwrap().0, "first");
        assert_eq!(
            bound
                .select_engagement(Some("missing"))
                .err()
                .unwrap()
                .code(),
            ErrorCode::ObjectNotFound
        );
        let binding = binding_file(&root, &state);
        fs::write(&binding, b"{}").unwrap();
        assert_eq!(
            select(&nested, None, &state).err().unwrap().code(),
            ErrorCode::WorkspaceUnbound
        );
    }
    #[test]
    fn two_engagements_require_explicit_selection() {
        let (_tmp, root, state) = setup();
        init(&root, &state, "first", ENGAGEMENT, Authority::default()).unwrap();
        let path = binding_file(&root, &state);
        let mut binding: Binding = crate::wire::from_slice(&fs::read(&path).unwrap()).unwrap();
        binding
            .engagements
            .insert("second".into(), ENGAGEMENT.to_vec());
        atomic_write(
            &state_dir(&state, false).unwrap(),
            path.file_name().unwrap().to_str().unwrap(),
            &serde_json::to_vec(&binding).unwrap(),
            false,
        )
        .unwrap();
        let bound = select(&root, Some(&root), &state).unwrap();
        assert_eq!(
            bound.engagements().collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(
            bound.select_engagement(None).err().unwrap().code(),
            ErrorCode::EngagementRequired
        );
        assert_eq!(bound.select_engagement(Some("second")).unwrap().0, "second");
    }
    #[test]
    fn hostile_nested_config_cannot_grant_authority_or_follow_symlinks() {
        let (tmp, root, state) = setup();
        init(&root, &state, "first", ENGAGEMENT, Authority::default()).unwrap();
        let nested = root.join("hostile");
        fs::create_dir(&nested).unwrap();
        let sentinel = tmp.path().join("sentinel");
        let foreign = tmp.path().join("foreign");
        fs::write(&foreign, b"foreign secret").unwrap();
        symlink(&foreign, nested.join("evidence")).unwrap();
        fs::write(
            nested.join(CONFIG),
            format!(
                "version = 1\nworkspace_id = \"{}\"\nadapter = \"{}\"\nevidence_root = \"{}\"\n",
                Uuid::new_v4(),
                sentinel.display(),
                nested.join("evidence").display()
            ),
        )
        .unwrap();
        assert_eq!(
            select(&nested, None, &state).err().unwrap().code(),
            ErrorCode::WorkspaceUnbound
        );
        assert!(!sentinel.exists());
        assert_eq!(fs::read(&foreign).unwrap(), b"foreign secret");
        assert!(
            select(&nested, Some(&root), &state)
                .unwrap()
                .authority
                .evidence_root
                .is_none()
        );
        fs::remove_file(nested.join(CONFIG)).unwrap();
        symlink(root.join(CONFIG), nested.join(CONFIG)).unwrap();
        assert_eq!(
            select(&nested, None, &state).err().unwrap().code(),
            ErrorCode::WorkspaceUnbound
        );
        let binding = binding_file(&root, &state);
        fs::remove_file(&binding).unwrap();
        symlink(&foreign, &binding).unwrap();
        assert_eq!(
            select(&root, None, &state).err().unwrap().code(),
            ErrorCode::WorkspaceUnbound
        );
    }
    #[test]
    fn rejects_bad_engagement_and_unsafe_state() {
        let (tmp, root, state) = setup();
        assert_eq!(
            init(&root, &state, "bad", b"{}", Authority::default())
                .err()
                .unwrap()
                .code(),
            ErrorCode::SchemaInvalid
        );
        assert!(!root.exists());
        init(&root, &state, "ok", ENGAGEMENT, Authority::default()).unwrap();
        fs::set_permissions(state.join("scourge"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            select(&root, None, &state).err().unwrap().code(),
            ErrorCode::WorkspaceUnbound
        );
        let alias = tmp.path().join("alias");
        symlink(&state, &alias).unwrap();
        assert_eq!(
            select(&root, None, &alias).err().unwrap().code(),
            ErrorCode::WorkspaceUnbound
        );
    }
}

#[cfg(test)]
mod regression_repro {
    use super::*;
    const E: &[u8] = include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");
    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("root");
        let s = t.path().join("state");
        fs::create_dir(&s).unwrap();
        (t, r, s)
    }
    #[test]
    fn repro_overlap() {
        let (_t, _r, state) = setup();
        let root = state.join("scourge");
        fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(init(&root, &state, "e", E, Authority::default()).is_err());
    }
    #[test]
    fn repro_relative_authority() {
        let (_t, root, state) = setup();
        let mut a = Authority::default();
        a.executables.insert("adapter".into(), "./evil".into());
        assert!(init(&root, &state, "e", E, a).is_err());
    }
    #[test]
    fn repro_retry_after_config() {
        let (_t, root, state) = setup();
        init(&root, &state, "e", E, Authority::default()).unwrap();
        let cfg = fs::read(root.join(CONFIG)).unwrap();
        fs::remove_file(state.join("scourge").join(key(&root, &cfg))).unwrap();
        assert!(init(&root, &state, "e", E, Authority::default()).is_ok());
    }
    #[test]
    fn repro_oversized_binding() {
        let (_t, root, state) = setup();
        let mut input = E.to_vec();
        input.extend_from_slice(b"\n#");
        input.extend(std::iter::repeat_n(120, 300_000));
        input.push(10);
        let result = init(&root, &state, "e", &input, Authority::default());
        assert!(result.is_err() || select(&root, None, &state).is_ok());
    }
    #[test]
    fn repro_discovery_error_is_not_absence() {
        let mut calls = 0;
        let result = discover_with(Path::new("/near/child"), |_| {
            calls += 1;
            if calls == 1 {
                Err(std::io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(WorkspaceError::Unbound)));
        assert_eq!(calls, 1);
    }
}

#[cfg(test)]
mod review_regressions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    const E: &[u8] = include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");
    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        let state = temp.path().join("state");
        fs::create_dir(&state).unwrap();
        (temp, root, state)
    }
    #[test]
    fn retries_after_each_durable_publication_and_preserves_foreign_config() {
        for stage in ["intent", "binding", "config"] {
            let (_temp, root, state) = setup();
            let error = init_with_hook(&root, &state, "one", E, Authority::default(), |point| {
                if stage == point {
                    Err(std::io::Error::other("injected interruption"))
                } else {
                    Ok(())
                }
            });
            assert!(error.is_err());
            init(&root, &state, "one", E, Authority::default()).unwrap();
            assert!(select(&root, None, &state).is_ok());
            assert!(init(&root, &state, "different", E, Authority::default()).is_err());
        }
        let (_temp, root, state) = setup();
        fs::create_dir(&root).unwrap();
        fs::write(root.join(CONFIG), b"foreign config").unwrap();
        assert!(init(&root, &state, "one", E, Authority::default()).is_err());
        assert_eq!(fs::read(root.join(CONFIG)).unwrap(), b"foreign config");
    }
    #[test]
    fn overlap_rejected_in_both_directions() {
        let (_temp, root, state) = setup();
        let store = state.join("scourge");
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        for path in [&state, &store, &store.join("child")] {
            assert!(init(path, &state, "one", E, Authority::default()).is_err());
        }
        init(&root, &state, "one", E, Authority::default()).unwrap();
        assert!(select(&root, Some(&store), &state).is_err());
    }
    #[test]
    fn each_relative_locator_is_rejected_on_init_and_binding_readback() {
        for field in 0..3 {
            let (_temp, root, state) = setup();
            let mut authority = Authority::default();
            match field {
                0 => {
                    authority
                        .executables
                        .insert("tool".into(), "relative/tool".into());
                }
                1 => authority.evidence_root = Some("../evidence".into()),
                _ => {
                    authority
                        .sockets
                        .insert("broker".into(), "broker.sock".into());
                }
            }
            assert!(init(&root, &state, "one", E, authority.clone()).is_err());
            init(&root, &state, "one", E, Authority::default()).unwrap();
            let config = fs::read(root.join(CONFIG)).unwrap();
            let path = state.join("scourge").join(key(&root, &config));
            let mut binding: Binding = crate::wire::from_slice(&fs::read(&path).unwrap()).unwrap();
            binding.authority = authority;
            fs::write(path, serde_json::to_vec(&binding).unwrap()).unwrap();
            assert!(select(&root, None, &state).is_err());
        }
    }
    #[test]
    fn bounded_encoding_rejects_before_publishing_and_smaller_input_survives_restart() {
        let (_temp, root, state) = setup();
        let mut oversized = E.to_vec();
        oversized.extend_from_slice(b"\n#");
        oversized.extend(std::iter::repeat_n(120, 300_000));
        oversized.push(10);
        assert!(init(&root, &state, "one", &oversized, Authority::default()).is_err());
        assert!(!root.join(CONFIG).exists());
        let mut smaller = E.to_vec();
        smaller.extend_from_slice(b"\n#");
        smaller.extend(std::iter::repeat_n(120, 100_000));
        smaller.push(10);
        init(&root, &state, "one", &smaller, Authority::default()).unwrap();
        assert!(select(&root, None, &state).is_ok());
    }
    #[test]
    fn fifo_config_is_never_read() {
        let (_temp, root, state) = setup();
        fs::create_dir(&root).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(root.join(CONFIG))
            .status()
            .unwrap();
        assert!(status.success());
        let dir = open_dir(&root).unwrap();
        let fd = rfs::openat(
            &dir,
            CONFIG,
            OFlags::RDWR | OFlags::NONBLOCK | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let mut fifo = File::from(fd);
        fifo.write_all(b"foreign bytes").unwrap();
        assert!(select(&root, None, &state).is_err());
        let mut remaining = [0; 13];
        fifo.read_exact(&mut remaining).unwrap();
        assert_eq!(&remaining, b"foreign bytes");
    }
}

#[cfg(test)]
mod remaining_repro {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    const E: &[u8] = include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");
    #[test]
    fn engagement_names_follow_frozen_identity_contract() {
        for value in [
            "",
            "my.engagement",
            "space name",
            "a/b",
            "\0",
            "Ω",
            &"x".repeat(100),
        ] {
            assert_eq!(
                valid_name(value),
                value.parse::<crate::ids::EngagementId>().is_ok()
            );
        }
    }
    #[test]
    fn add_retry_flushes_after_visible_rename() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir(&state).unwrap();
        init(&root, &state, "one", E, Authority::default()).unwrap();
        let fail = |stage: &str| {
            if stage == "binding_flush" {
                Err(std::io::Error::other("injected fsync failure"))
            } else {
                Ok(())
            }
        };
        assert!(add_engagement_with_hook(&root, None, &state, "two", E, fail).is_err());
        assert!(add_engagement_with_hook(&root, None, &state, "two", E, fail).is_err());
        add_engagement(&root, None, &state, "two", E).unwrap();
        assert!(
            select(&root, None, &state)
                .unwrap()
                .select_engagement(Some("two"))
                .is_ok()
        );
    }
    #[test]
    fn checked_state_handle_cannot_be_redirected_by_rename() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&state).unwrap();
        fs::create_dir(root.join("foreign")).unwrap();
        fs::set_permissions(root.join("foreign"), fs::Permissions::from_mode(0o700)).unwrap();
        let original = temp.path().join("original");
        init_with_hook(&root, &state, "one", E, Authority::default(), |stage| {
            if stage == "directories_checked" {
                fs::rename(state.join("scourge"), &original)?;
                fs::rename(root.join("foreign"), state.join("scourge"))?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read_dir(state.join("scourge")).unwrap().count(), 0);
        assert!(fs::read_dir(&original).unwrap().count() >= 2);
        fs::rename(state.join("scourge"), root.join("foreign")).unwrap();
        fs::rename(&original, state.join("scourge")).unwrap();
        assert!(select(&root, None, &state).is_ok());
        let selected = select_with_hook(&root, None, &state, || {
            fs::rename(state.join("scourge"), &original)?;
            fs::rename(root.join("foreign"), state.join("scourge"))?;
            Ok(())
        });
        assert!(selected.is_ok());
        assert_eq!(fs::read_dir(state.join("scourge")).unwrap().count(), 0);
        fs::rename(state.join("scourge"), root.join("foreign")).unwrap();
        fs::rename(original, state.join("scourge")).unwrap();
    }
    #[test]
    fn retry_flush_failure_is_never_success_and_preserves_unrelated_state() {
        for stage in [
            "state_parent_flush",
            "intent_flush",
            "coordination_parent_flush",
            "coordination_flush",
            "binding_flush",
            "config_flush",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let state = temp.path().join("state");
            fs::create_dir(&state).unwrap();
            fs::write(state.join("unrelated"), b"keep").unwrap();
            let fail = |point: &str| {
                if point == stage {
                    Err(std::io::Error::other("injected flush failure"))
                } else {
                    Ok(())
                }
            };
            assert!(init_with_hook(&root, &state, "one", E, Authority::default(), fail).is_err());
            assert!(init_with_hook(&root, &state, "one", E, Authority::default(), fail).is_err());
            assert_eq!(fs::read(state.join("unrelated")).unwrap(), b"keep");
            init(&root, &state, "one", E, Authority::default()).unwrap();
            assert!(select(&root, None, &state).is_ok());
        }
    }

    #[test]
    fn add_recovery_keeps_the_coordination_inode_and_withholds_unpublished_names() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir(&state).unwrap();
        init(&root, &state, "one", E, Authority::default()).unwrap();
        let path = root.join(".scourge/state.sqlite3");
        let inode = fs::metadata(&path).unwrap().ino();
        let failure = add_engagement_with_hook(&root, None, &state, "two", E, |stage| {
            if stage == "coordination_flush" {
                Err(std::io::Error::other(
                    "injected coordination publish failure",
                ))
            } else {
                Ok(())
            }
        });
        assert!(failure.is_err());
        let old = select(&root, None, &state).unwrap();
        assert!(old.select_engagement(Some("two")).is_err());
        assert!(old.open_coordination().is_ok());
        let writer = crate::store::Store::open(&path).unwrap();
        let revision = writer.revision().unwrap();
        drop(writer);
        add_engagement(&root, None, &state, "two", E).unwrap();
        add_engagement(&root, None, &state, "two", E).unwrap();
        let workspace = select(&root, None, &state).unwrap();
        assert!(workspace.select_engagement(Some("two")).is_ok());
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        assert_eq!(
            crate::store::Store::open(&path)
                .unwrap()
                .revision()
                .unwrap(),
            revision
        );
    }

    #[test]
    fn bound_coordination_refuses_symlinks_and_other_store_identities() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let foreign = temp.path().join("foreign");
        let state = temp.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&root).unwrap();
        init(&foreign, &state, "one", E, Authority::default()).unwrap();
        let foreign_path = foreign.join(".scourge/state.sqlite3");
        let original = fs::read(&foreign_path).unwrap();
        symlink(foreign.join(".scourge"), root.join(".scourge")).unwrap();
        assert!(matches!(
            init(&root, &state, "one", E, Authority::default()),
            Err(WorkspaceError::CoordinationInvalid)
        ));
        assert!(!root.join("scourge.toml").exists());
        assert_eq!(fs::read(&foreign_path).unwrap(), original);

        fs::remove_file(root.join(".scourge")).unwrap();
        let workspace = init(&root, &state, "one", E, Authority::default()).unwrap();
        assert_eq!(
            fs::metadata(root.join(".scourge")).unwrap().mode() & 0o777,
            0o700
        );
        let local = root.join(".scourge/state.sqlite3");
        let backup = root.join(".scourge/original");
        assert_eq!(fs::metadata(&local).unwrap().mode() & 0o777, 0o600);
        fs::rename(&local, &backup).unwrap();
        symlink(&foreign_path, &local).unwrap();
        assert!(matches!(
            workspace.open_coordination(),
            Err(WorkspaceError::CoordinationInvalid)
        ));
        assert!(matches!(
            add_engagement(&root, None, &state, "two", E),
            Err(WorkspaceError::CoordinationInvalid)
        ));
        assert_eq!(fs::read(&foreign_path).unwrap(), original);

        fs::remove_file(&local).unwrap();
        fs::create_dir(&local).unwrap();
        assert!(matches!(
            workspace.open_coordination(),
            Err(WorkspaceError::CoordinationInvalid)
        ));
        fs::remove_dir(&local).unwrap();
        fs::copy(&foreign_path, &local).unwrap();
        assert!(matches!(
            workspace.open_coordination(),
            Err(WorkspaceError::Coordination(
                crate::store::StoreError::Integrity
            ))
        ));
        assert!(add_engagement(&root, None, &state, "two", E).is_err());
        assert_eq!(fs::read(&local).unwrap(), original);
        fs::rename(backup, local).unwrap();
        assert!(workspace.open_coordination().is_ok());
    }
    #[test]
    fn state_directory_moved_into_workspace_is_rejected_before_binding_access() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&state).unwrap();
        let result = init_with_hook(&root, &state, "one", E, Authority::default(), |stage| {
            if stage == "directories_checked" {
                fs::rename(state.join("scourge"), root.join("moved-state"))?;
            }
            Ok(())
        });
        assert!(matches!(result, Err(WorkspaceError::Unbound)));
        assert_eq!(fs::read_dir(root.join("moved-state")).unwrap().count(), 0);
        assert!(!root.join(CONFIG).exists());
    }
}

#[cfg(test)]
pub(crate) mod runtime_authority_tests {
    use super::*;
    use crate::engagement::{EngagementDraft, PassPin};

    pub(crate) const DECLARATION: &[u8] =
        include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");

    fn runtime() -> VerifierRuntimeAuthority {
        runtime_for(DECLARATION)
    }

    pub(crate) fn runtime_for(declaration: &[u8]) -> VerifierRuntimeAuthority {
        let draft = EngagementDraft::parse_toml(declaration).unwrap();
        let reference = draft.settings().pass_ref.clone();
        let digest = Sha256Digest::of(b"pass");
        let manifest = draft
            .accept(PassPin {
                reference: &reference,
                digest: &digest,
            })
            .unwrap();
        VerifierRuntimeAuthority {
            manifest: ManifestAuthority {
                revision: manifest.revision(),
                digest: manifest.digest().clone(),
                canonical_bytes: manifest.canonical_bytes().to_vec(),
                artifact: ManifestArtifactPin {
                    kind: ManifestArtifactKind::EngagementManifest,
                    reference: crate::wire::Artifact {
                        artifact_id: "art_12345678-1234-4234-8234-123456789abc".parse().unwrap(),
                        digest: manifest.digest().clone(),
                    },
                    revision: 1,
                    size_bytes: manifest.canonical_bytes().len(),
                    source_id: "src_12345678-1234-4234-8234-123456789abc".parse().unwrap(),
                },
            },
            pass: PassAuthority {
                path: "/never-open/pass".into(),
                digest,
            },
            teapot: TeapotProjectAuthority {
                executable: "/never-open/teapot".into(),
                project: "/never-open/project".into(),
                home: "/never-open/home".into(),
                config_home: None,
                data_home: None,
                state_home: None,
                cache_home: None,
                runtime_dir: None,
                wrapper: false,
            },
            engine: crate::teapot::BoundEngine {
                instance: "engine".parse().unwrap(),
                project_id: "project".parse().unwrap(),
                enforced: true,
                policy_locked: true,
            },
            investigation: InvestigationAuthority {
                executable: "/never-open/investigation".into(),
                case_root: "/never-open/cases".into(),
                workspace_root: "/never-open/cases/workspace".into(),
                import_root: "/never-open/import".into(),
                scratch_root: "/never-open/scratch".into(),
            },
            target: manifest.target_version().clone(),
            origin: crate::rounds::TargetOrigin::parse("http://127.0.0.1:1").unwrap(),
            environment_kind: crate::wire::EnvironmentKind::Simulated,
            custody: crate::wire::Custody::Shared,
            target_isolation: crate::wire::TargetIsolation::SeparatePrincipalsUnconfined,
            principal_slots: BTreeMap::new(),
        }
    }

    fn workspace(binding: VerifierRuntimeAuthority) -> BoundWorkspace {
        workspace_for(binding, DECLARATION)
    }

    pub(crate) fn workspace_for(
        binding: VerifierRuntimeAuthority,
        declaration: &[u8],
    ) -> BoundWorkspace {
        BoundWorkspace {
            root: "/never-open".into(),
            workspace_id: "unused".into(),
            authority: Authority {
                verifier_runtime: [("one".into(), binding)].into(),
                ..Authority::default()
            },
            engagements: [("one".into(), declaration.to_vec())].into(),
        }
    }

    #[test]
    fn request_scope_uses_private_identity_and_registered_engagement() {
        let mut bound = workspace(runtime());
        bound.workspace_id = Uuid::new_v4().to_string();
        let engagement = "one".parse().unwrap();
        let original = bound.request_scope(&engagement).unwrap();
        bound.root = "/some/other/path".into();
        assert_eq!(bound.request_scope(&engagement).unwrap(), original);

        bound.workspace_id = Uuid::new_v4().to_string();
        assert_ne!(bound.request_scope(&engagement).unwrap(), original);
        assert!(matches!(
            bound.request_scope(&"unregistered".parse().unwrap()),
            Err(WorkspaceError::EngagementNotFound)
        ));
    }

    #[test]
    fn old_bindings_and_complete_roundtrip() {
        let old = r#"{"executables":{},"evidence_root":null,"credential_sources":{},"sockets":{}}"#;
        let authority: Authority = serde_json::from_str(old).unwrap();
        assert_eq!(authority, Authority::default());
        let binding = runtime();
        assert_eq!(
            serde_json::from_slice::<VerifierRuntimeAuthority>(
                &serde_json::to_vec(&binding).unwrap()
            )
            .unwrap(),
            binding
        );
        let mut partial = serde_json::to_value(&binding).unwrap();
        partial.as_object_mut().unwrap().remove("engine");
        assert!(serde_json::from_value::<VerifierRuntimeAuthority>(partial).is_err());
        let mut extra = serde_json::to_value(&binding).unwrap();
        extra["unexpected"] = true.into();
        assert!(serde_json::from_value::<VerifierRuntimeAuthority>(extra).is_err());
        for key in ["kind", "reference", "revision", "size_bytes", "source_id"] {
            let mut partial = serde_json::to_value(&binding).unwrap();
            partial["manifest"]["artifact"]
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(serde_json::from_value::<VerifierRuntimeAuthority>(partial).is_err());
        }
        let mut missing = serde_json::to_value(&binding).unwrap();
        missing["manifest"]
            .as_object_mut()
            .unwrap()
            .remove("artifact");
        assert!(serde_json::from_value::<VerifierRuntimeAuthority>(missing).is_err());
        let mut extra = serde_json::to_value(&binding).unwrap();
        extra["manifest"]["artifact"]["extra"] = true.into();
        assert!(serde_json::from_value::<VerifierRuntimeAuthority>(extra).is_err());
        let mut wrong_kind = serde_json::to_value(&binding).unwrap();
        wrong_kind["manifest"]["artifact"]["kind"] = "experiment".into();
        assert!(serde_json::from_value::<VerifierRuntimeAuthority>(wrong_kind).is_err());
        let mut bad_digest = serde_json::to_value(&binding).unwrap();
        bad_digest["manifest"]["artifact"]["reference"]["digest"] = "not-a-digest".into();
        assert!(serde_json::from_value::<VerifierRuntimeAuthority>(bad_digest).is_err());
    }

    #[test]
    fn validation_rejects_paths_pins_and_conflicting_slots() {
        let binding = runtime();
        assert!(valid_runtime(&binding));
        let mut bad = binding.clone();
        bad.pass.path = "/a/../pass".into();
        assert!(!valid_runtime(&bad));
        let mut bad = binding.clone();
        bad.investigation.executable = "relative".into();
        assert!(!valid_runtime(&bad));
        let mut bad = binding.clone();
        bad.manifest.digest = Sha256Digest::of(b"wrong");
        assert!(!valid_runtime(&bad));
        let mut bad = binding.clone();
        bad.pass.digest = Sha256Digest::of(b"wrong");
        assert!(!valid_runtime(&bad));
        let mut bad = binding.clone();
        bad.manifest.artifact.reference.digest = Sha256Digest::of(b"wrong");
        assert!(!valid_runtime(&bad));
        let mut bad = binding.clone();
        bad.manifest.artifact.size_bytes += 1;
        assert!(!valid_runtime(&bad));
        let mut bad = binding.clone();
        bad.manifest.artifact.revision = 0;
        assert!(!valid_runtime(&bad));
        let mut bad = binding.clone();
        bad.manifest.artifact.reference.artifact_id = "art_bad".parse().unwrap();
        assert!(!valid_runtime(&bad));
        let mut bad = binding.clone();
        bad.manifest.artifact.source_id = "src_bad".parse().unwrap();
        assert!(!valid_runtime(&bad));
        let mut bad = binding;
        let slot = TrustedPrincipalSlot {
            principal: "alice".parse().unwrap(),
            provenance: "operator".parse().unwrap(),
        };
        bad.principal_slots
            .insert("owner".parse().unwrap(), slot.clone());
        bad.principal_slots.insert("other".parse().unwrap(), slot);
        assert!(!valid_runtime(&bad));
    }

    #[test]
    fn retained_manifest_pin_checks_each_artifact_field() {
        let pin = runtime().manifest.artifact;
        let retained = RetainedArtifact {
            reference: pin.reference.clone(),
            revision: pin.revision,
            size_bytes: pin.size_bytes,
            source_id: pin.source_id.as_str().to_owned(),
            lineage: Vec::new(),
        };
        pin.check(&retained).unwrap();
        let mut wrong = retained.clone();
        wrong.reference.artifact_id = "art_10000000-0000-4000-8000-000000000009".parse().unwrap();
        assert!(matches!(pin.check(&wrong), Err(EvidenceError::Integrity)));
        let mut wrong = retained.clone();
        wrong.reference.digest = Sha256Digest::of(b"wrong");
        assert!(matches!(pin.check(&wrong), Err(EvidenceError::Integrity)));
        let mut wrong = retained.clone();
        wrong.revision += 1;
        assert!(matches!(pin.check(&wrong), Err(EvidenceError::Integrity)));
        let mut wrong = retained.clone();
        wrong.size_bytes += 1;
        assert!(matches!(pin.check(&wrong), Err(EvidenceError::Integrity)));
        let mut wrong = retained;
        wrong.source_id = "src_10000000-0000-4000-8000-000000000009".to_owned();
        assert!(matches!(pin.check(&wrong), Err(EvidenceError::Integrity)));
    }

    #[test]
    fn manifest_open_retries_snapshot_movement_and_preserves_integrity_failures() {
        let mut checks = 0;
        retry_manifest_check(|| {
            checks += 1;
            if checks == 1 {
                Err(EvidenceError::ChangedSnapshot)
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(checks, 2);

        let mut checks = 0;
        assert!(matches!(
            retry_manifest_check(|| {
                checks += 1;
                Err(EvidenceError::ChangedSnapshot)
            }),
            Err(EvidenceError::ChangedSnapshot)
        ));
        assert_eq!(checks, 3);

        let mut checks = 0;
        assert!(matches!(
            retry_manifest_check(|| {
                checks += 1;
                Err(EvidenceError::Integrity)
            }),
            Err(EvidenceError::Integrity)
        ));
        assert_eq!(checks, 1);
    }

    #[test]
    fn resolution_is_inert_and_checks_selected_engagement() {
        // None of these paths exist and the origin has no listener. Success
        // demonstrates that resolution needs neither adapters nor a socket.
        let mut bound = workspace(runtime());
        assert!(bound.resolve_verifier_runtime("one").is_ok());
        assert!(matches!(
            bound.resolve_verifier_runtime("absent"),
            Err(RuntimeAuthorityError::Conflict)
        ));
        bound.authority.verifier_runtime.clear();
        assert!(matches!(
            bound.resolve_verifier_runtime("one"),
            Err(RuntimeAuthorityError::Missing)
        ));
        bound
            .authority
            .verifier_runtime
            .insert("one".into(), runtime());
        bound
            .engagements
            .insert("one".into(), b"different".to_vec());
        assert!(matches!(
            bound.resolve_verifier_runtime("one"),
            Err(RuntimeAuthorityError::Conflict)
        ));
    }

    #[test]
    fn selection_rejects_missing_or_inconsistent_artifact_pin() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir(&state).unwrap();
        let authority = Authority {
            verifier_runtime: [("one".into(), runtime())].into(),
            ..Authority::default()
        };
        init(&root, &state, "one", DECLARATION, authority).unwrap();
        assert!(
            select(&root, None, &state)
                .unwrap()
                .resolve_verifier_runtime("one")
                .is_ok()
        );
        let config = fs::read(root.join(CONFIG)).unwrap();
        let path = state.join("scourge").join(key(&root, &config));
        let bytes = fs::read(&path).unwrap();
        let mut stored: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        stored["authority"]["verifier_runtime"]["one"]["manifest"]
            .as_object_mut()
            .unwrap()
            .remove("artifact");
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert!(matches!(
            select(&root, None, &state),
            Err(WorkspaceError::Unbound)
        ));
        let mut stored: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        stored["authority"]["verifier_runtime"]["one"]["manifest"]["artifact"]["size_bytes"] =
            0.into();
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert!(matches!(
            select(&root, None, &state),
            Err(WorkspaceError::Unbound)
        ));
    }
}
