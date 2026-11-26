//! Inode-bound setup receipt for the local tutorial.

use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};

use rustix::fs::{self as rfs, AtFlags, FlockOperation, Mode, OFlags};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DemoControl {
    pub socket: PathBuf,
    pub expires: i64,
    pub token: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct NamedDirectoryIdentity {
    pub(super) name: String,
    pub(super) identity: DirectoryIdentity,
}

impl DirectoryIdentity {
    pub(super) fn read(dir: &File) -> io::Result<Self> {
        let stat = rfs::fstat(dir)?;
        Ok(Self {
            device: stat.st_dev,
            inode: stat.st_ino,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DemoIntent {
    directory: DirectoryIdentity,
    config: Vec<u8>,
    workspace_id: Uuid,
    attempt: Uuid,
    binding: Option<Binding>,
    #[serde(default)]
    lease: Option<DirectoryIdentity>,
    #[serde(default)]
    coordination: Option<NamedDirectoryIdentity>,
    #[serde(default)]
    abandoned: Vec<AbandonedRuntime>,
    #[serde(default)]
    retired: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AbandonedRuntime {
    attempt: Uuid,
    home: NamedDirectoryIdentity,
    lease: DirectoryIdentity,
}

pub struct DemoWorkspace {
    path: PathBuf,
    root: File,
    state_path: PathBuf,
    state: File,
    _lock: File,
    intent: Option<DemoIntent>,
}

pub struct DemoAnchor {
    path: PathBuf,
    root: File,
    state_path: PathBuf,
    state: File,
    attempt: Uuid,
    control: DemoControl,
    config: Option<File>,
}

fn demo_key(root: &Path) -> String {
    format!("demo-{}", key(root, b"local-tutorial-v1"))
}

fn claim_name(root: &Path) -> String {
    format!("claim-{}", key(root, b"workspace-claim-v1"))
}

pub(super) fn reserve_ordinary(root: &Path, state: &File) -> Result<File, WorkspaceError> {
    let lock = private_lock(state, &claim_name(root), true)?;
    if present(state, &demo_key(root))? {
        return Err(WorkspaceError::Unbound);
    }
    Ok(lock)
}

fn present(dir: &File, name: &str) -> io::Result<bool> {
    match rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn private_lock(dir: &File, name: &str, create: bool) -> io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let lock = File::from(rfs::openat(
        dir,
        name,
        if create {
            flags | OFlags::CREATE
        } else {
            flags
        },
        Mode::from_raw_mode(0o600),
    )?);
    let metadata = rfs::fstat(&lock)?;
    if rfs::FileType::from_raw_mode(metadata.st_mode) != rfs::FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o077 != 0
    {
        return Err(io::Error::other("unsafe demo lock"));
    }
    rfs::flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
    Ok(lock)
}

fn load_intent(
    path: &Path,
    root: &File,
    state: &File,
) -> Result<Option<DemoIntent>, WorkspaceError> {
    match read_private(state, &demo_key(path)) {
        Ok(bytes) => {
            let intent: DemoIntent =
                crate::wire::from_slice(&bytes).map_err(|_| WorkspaceError::Unbound)?;
            if intent.directory != DirectoryIdentity::read(root)?
                || (present(root, CONFIG)? && !same_config(root, &intent.config)?)
            {
                return Err(WorkspaceError::Unbound);
            }
            Ok(Some(intent))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn same_config(root: &File, expected: &[u8]) -> io::Result<bool> {
    let config = nofollow_file(root, CONFIG)?;
    Ok(config.metadata()?.is_file() && read_limited(config)? == expected)
}

/// Open or create each component without following a symlink at any level.
pub fn create_demo_root(path: &Path) -> io::Result<()> {
    let path = normalize_demo_path(path)?;
    let mut directory = File::open("/")?;
    for part in path.components() {
        let Component::Normal(name) = part else {
            if part == Component::RootDir {
                continue;
            }
            return Err(io::Error::other("invalid demo path"));
        };
        let open = || {
            rfs::openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        };
        directory = File::from(match open() {
            Err(rustix::io::Errno::NOENT) => {
                match rfs::mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => (),
                    Err(error) => return Err(error.into()),
                }
                rfs::fsync(&directory)?;
                open()?
            }
            value => value?,
        });
    }
    Ok(())
}

/// Produce the one absolute lexical spelling used by every demo key, binding,
/// response, and generated command without resolving any filesystem link.
pub fn normalize_demo_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::from("/");
    for part in absolute.components() {
        match part {
            Component::RootDir | Component::CurDir => (),
            Component::Normal(name) => normalized.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::other("invalid demo path"));
            }
        }
    }
    Ok(normalized)
}

/// Retain exact directory handles for setup, recovery, and publication.
pub fn check_demo_root(root: &Path, state: &Path) -> Result<DemoWorkspace, WorkspaceError> {
    let root = normalize_demo_path(root).map_err(|_| WorkspaceError::Unbound)?;
    let dir = open_dir(&root).map_err(|_| WorkspaceError::Unbound)?;
    let sd = state_dir_with(state, true, &mut |_| Ok(()))?;
    independent_state(&dir, &sd)?;
    let stat = rfs::fstat(&dir).map_err(io::Error::from)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o022 != 0 {
        return Err(WorkspaceError::Unbound);
    }
    let intent = load_intent(&root, &dir, &sd)?;
    if present(&sd, &pending_key(&root))?
        || (intent.is_none() && (present(&dir, CONFIG)? || present(&dir, ".scourge")?))
    {
        return Err(WorkspaceError::Unbound);
    }
    let lock = private_lock(&sd, &claim_name(&root), true)?;
    let intent = load_intent(&root, &dir, &sd)?;
    if present(&sd, &pending_key(&root))?
        || (intent.is_none() && (present(&dir, CONFIG)? || present(&dir, ".scourge")?))
    {
        return Err(WorkspaceError::Unbound);
    }
    Ok(DemoWorkspace {
        path: root,
        root: dir,
        state_path: state.to_owned(),
        state: sd,
        _lock: lock,
        intent,
    })
}

/// A supervisor can act on a pending tutorial before ordinary workspace
/// selection is enabled. Only the matching private control receipt opens it.
pub fn demo_pending(root: &Path, state: &Path, control: &DemoControl) -> Option<DemoAnchor> {
    let root = normalize_demo_path(root).ok()?;
    let dir = open_dir(&root).ok()?;
    let state_dir = state_dir_with(state, false, &mut |_| Ok(())).ok()?;
    independent_state(&dir, &state_dir).ok()?;
    let intent = load_intent(&root, &dir, &state_dir).ok()??;
    let matches = !intent.retired && intent.binding?.authority.demo.as_ref() == Some(control);
    matches.then(|| DemoAnchor {
        path: root,
        root: dir,
        state_path: state.to_owned(),
        state: state_dir,
        attempt: intent.attempt,
        control: control.clone(),
        config: None,
    })
}

/// Recover the authenticated control receipt from the private intent when the
/// public config/binding path is unavailable.
pub fn demo_fallback_control(root: &Path, state: &Path) -> Option<(PathBuf, DemoControl)> {
    let root = normalize_demo_path(root).ok()?;
    let dir = open_dir(&root).ok()?;
    let state_dir = state_dir_with(state, false, &mut |_| Ok(())).ok()?;
    independent_state(&dir, &state_dir).ok()?;
    let intent = load_intent(&root, &dir, &state_dir).ok()??;
    let control = intent.binding?.authority.demo?;
    (!intent.retired).then_some((root, control))
}

pub fn demo_root_is_current(root: &Path, original: &File) -> bool {
    let check = || {
        let current = open_dir(&normalize_demo_path(root)?)?;
        Ok::<_, io::Error>(DirectoryIdentity::read(&current)? == DirectoryIdentity::read(original)?)
    };
    check().unwrap_or(false)
}

impl DemoAnchor {
    pub fn current(&self) -> bool {
        let check = || -> Result<bool, WorkspaceError> {
            let root = open_dir(&self.path)?;
            let state = state_dir_with(&self.state_path, false, &mut |_| Ok(()))?;
            Ok::<_, WorkspaceError>(
                DirectoryIdentity::read(&root)? == DirectoryIdentity::read(&self.root)?
                    && DirectoryIdentity::read(&state)? == DirectoryIdentity::read(&self.state)?
                    && independent_state(&self.root, &self.state).is_ok(),
            )
        };
        check().unwrap_or(false)
    }

    fn visible(&self) -> bool {
        let check = || -> Result<bool, WorkspaceError> {
            if !self.current() {
                return Ok(false);
            }
            let intent =
                load_intent(&self.path, &self.root, &self.state)?.ok_or(WorkspaceError::Unbound)?;
            if intent.retired
                || intent.attempt != self.attempt
                || intent
                    .binding
                    .as_ref()
                    .and_then(|binding| binding.authority.demo.as_ref())
                    != Some(&self.control)
                || !present(&self.state, &key(&self.path, &intent.config))?
            {
                return Ok(false);
            }
            let (binding, _) = read_binding(&self.path, &self.root, &self.state)?;
            Ok(intent.binding.as_ref() == Some(&binding))
        };
        check().unwrap_or(false)
    }

    pub fn activate(&mut self) -> bool {
        if !self.visible() {
            return false;
        }
        let check = || {
            let named = rfs::statat(&self.root, CONFIG, AtFlags::SYMLINK_NOFOLLOW)?;
            let config = nofollow_file(&self.root, CONFIG)?;
            let opened = rfs::fstat(&config)?;
            if named.st_dev != opened.st_dev || named.st_ino != opened.st_ino {
                return Err(io::Error::other("demo config changed during activation"));
            }
            Ok::<_, io::Error>(config)
        };
        match check() {
            Ok(config) => {
                self.config = Some(config);
                true
            }
            Err(_) => false,
        }
    }

    pub fn healthy(&self) -> bool {
        let Some(config) = &self.config else {
            return false;
        };
        let named = rfs::statat(&self.root, CONFIG, AtFlags::SYMLINK_NOFOLLOW);
        let opened = rfs::fstat(config);
        matches!((named, opened), (Ok(named), Ok(opened)) if named.st_dev == opened.st_dev && named.st_ino == opened.st_ino)
            && self.visible()
    }
}

pub fn demo_supervisor_lease(home: &Path) -> io::Result<File> {
    private_lock(&open_dir(home)?, "supervisor.lease", false)
}

impl DemoWorkspace {
    pub fn root(&self) -> &Path {
        &self.path
    }

    pub fn check_guide(&self) -> Result<(), managed_guide::Error> {
        managed_guide::check(&self.root)
    }

    pub fn authority(&self) -> Option<&Authority> {
        self.intent
            .as_ref()?
            .binding
            .as_ref()
            .map(|binding| &binding.authority)
    }

    pub fn active(&self) -> Result<bool, WorkspaceError> {
        self.current()?;
        let Some(intent) = &self.intent else {
            return Ok(false);
        };
        if !present(&self.state, &key(&self.path, &intent.config))? {
            return Ok(false);
        }
        let (active, _) = read_binding(&self.path, &self.root, &self.state)?;
        let pending = intent.binding.as_ref().ok_or(WorkspaceError::Unbound)?;
        if active.workspace_id != pending.workspace_id || active.authority != pending.authority {
            return Err(WorkspaceError::Unbound);
        }
        Ok(true)
    }

    pub fn reserve(&mut self) -> Result<PathBuf, WorkspaceError> {
        self.reserve_with(&mut |_| Ok(()))
    }

    fn reserve_with(
        &mut self,
        hook: &mut impl FnMut(&str) -> io::Result<()>,
    ) -> Result<PathBuf, WorkspaceError> {
        self.current()?;
        if self.intent.is_none() {
            let workspace_id = Uuid::new_v4();
            self.intent = Some(DemoIntent {
                directory: DirectoryIdentity::read(&self.root)?,
                config: config_bytes(&Config {
                    version: 1,
                    workspace_id: workspace_id.to_string(),
                })?,
                workspace_id,
                attempt: Uuid::new_v4(),
                binding: None,
                lease: None,
                coordination: None,
                abandoned: Vec::new(),
                retired: false,
            });
            self.save(true, "intent", hook)?;
        }
        let home = self.home_name();
        rfs::mkdirat(&self.state, home.as_str(), Mode::from_raw_mode(0o700))
            .map_err(io::Error::from)?;
        let dir = open_private_dir(&self.state, &home)?;
        let lease = private_lock(&dir, "supervisor.lease", true)?;
        hook("lease_created")?;
        self.intent.as_mut().expect("setup intent").lease = Some(DirectoryIdentity::read(&lease)?);
        rfs::fsync(&dir).map_err(io::Error::from)?;
        rfs::fsync(&self.state).map_err(io::Error::from)?;
        self.current()?;
        self.save(false, "lease", hook)?;
        Ok(self.state_path.join("scourge").join(home))
    }

    /// Abandon preparation only while the authoritative binding is absent and
    /// no supervisor holds the private lease. One-shot preparation children do
    /// not hold that lease and may outlive their parent, so the receipted tree
    /// is retained as their containment boundary and a fresh attempt is used.
    pub fn reset(&mut self) -> Result<(), WorkspaceError> {
        self.reset_with(&mut |_| Ok(()))
    }

    fn reset_with(
        &mut self,
        hook: &mut impl FnMut(&str) -> io::Result<()>,
    ) -> Result<(), WorkspaceError> {
        if self.intent.is_none() {
            return Ok(());
        }
        if self.active()? {
            return Err(WorkspaceError::Unbound);
        }
        let intent = self.intent.as_ref().expect("setup intent");
        let workspace_id = intent.workspace_id.to_string();
        let home = self.home_name();
        if intent.lease.is_none() {
            // reserve() cannot return, and the supervisor cannot start, until
            // the lease identity is durable in this intent. Preserve any name
            // created before that receipt and abandon the exact attempt.
            if intent.binding.is_some() || intent.coordination.is_some() {
                return Err(WorkspaceError::Unbound);
            }
            let intent = self.intent.as_mut().expect("setup intent");
            intent.attempt = Uuid::new_v4();
            intent.retired = false;
            return self.save(false, "reset", hook);
        }
        let dir = open_private_dir(&self.state, &home)?;
        let expected = intent.lease.expect("handled unreceipted attempt");
        let _lease = same_lease(&dir, expected)?;
        hook("reset_lease")?;
        coordination::discard_demo(&self.root, &workspace_id, intent.coordination.clone())?;
        hook("reset_coordination")?;
        verify_named_dir(&self.state, &home, &dir)?;
        let receipt = AbandonedRuntime {
            attempt: intent.attempt,
            home: NamedDirectoryIdentity {
                name: home.clone(),
                identity: DirectoryIdentity::read(&dir)?,
            },
            lease: expected,
        };
        let matches = self
            .intent
            .as_ref()
            .expect("setup intent")
            .abandoned
            .iter()
            .filter(|candidate| candidate.attempt == receipt.attempt)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => {
                self.intent
                    .as_mut()
                    .expect("setup intent")
                    .abandoned
                    .push(receipt);
                self.save(false, "abandonment_flush", hook)?;
            }
            [existing] if **existing == receipt => (),
            _ => return Err(WorkspaceError::Unbound),
        }
        hook("abandonment")?;
        let intent = self.intent.as_mut().expect("setup intent");
        intent.attempt = Uuid::new_v4();
        intent.binding = None;
        intent.lease = None;
        intent.coordination = None;
        intent.retired = false;
        self.save(false, "reset", hook)
    }

    /// Reconcile a confirmed-dead committed runtime while retaining the
    /// workspace, evidence, pass and acquisition history.
    pub fn retire(&mut self) -> Result<(), WorkspaceError> {
        if !self.confirm_active()? {
            return Err(WorkspaceError::Unbound);
        }
        let intent = self.intent.as_ref().expect("setup intent");
        if intent.retired {
            return Ok(());
        }
        let dir = open_private_dir(&self.state, &self.home_name())?;
        let _lease = same_lease(&dir, intent.lease.ok_or(WorkspaceError::Unbound)?)?;
        self.intent.as_mut().expect("setup intent").retired = true;
        self.save(false, "retired", &mut |_| Ok(()))?;
        self.current()
    }

    pub fn retired(&self) -> bool {
        self.intent.as_ref().is_some_and(|intent| intent.retired)
    }

    pub fn prepare(
        &mut self,
        name: &str,
        declaration: &[u8],
        authority: Authority,
    ) -> Result<(), WorkspaceError> {
        self.prepare_with(name, declaration, authority, &mut |_| Ok(()))
    }

    fn prepare_with(
        &mut self,
        name: &str,
        declaration: &[u8],
        authority: Authority,
        hook: &mut impl FnMut(&str) -> io::Result<()>,
    ) -> Result<(), WorkspaceError> {
        self.current()?;
        let intent = self.intent.as_mut().ok_or(WorkspaceError::Unbound)?;
        if intent.binding.is_some() || authority.demo.is_none() || !valid_authority(&authority) {
            return Err(WorkspaceError::Unbound);
        }
        if !valid_name(name) || !valid_engagement(declaration) {
            return Err(WorkspaceError::InvalidEngagement);
        }
        intent.binding = Some(Binding {
            version: 1,
            workspace_id: intent.workspace_id.to_string(),
            root: self.path.clone(),
            config_digest: Sha256Digest::of(&intent.config).as_str().to_owned(),
            demo_directory: Some(intent.directory),
            authority,
            engagements: [(name.to_owned(), declaration.to_vec())].into(),
        });
        self.save(false, "prepared", hook)
    }

    /// Enable ordinary selection only after the caller authenticated the
    /// supervisor. Before this commit point the private intent owns all setup.
    pub fn publish(&mut self, name: &str) -> Result<managed_guide::Receipt, DemoPublishError> {
        self.publish_with(name, &mut |_| Ok(()))
    }

    fn publish_with(
        &mut self,
        name: &str,
        hook: &mut impl FnMut(&str) -> io::Result<()>,
    ) -> Result<managed_guide::Receipt, DemoPublishError> {
        self.current()?;
        hook("demo_directories_checked")?;
        self.current()?;
        let binding = self
            .intent
            .as_ref()
            .and_then(|intent| intent.binding.clone())
            .ok_or(WorkspaceError::Unbound)?;
        let runtime = binding
            .authority
            .verifier_runtime
            .get(name)
            .ok_or(WorkspaceError::Unbound)?;
        let manifest = (
            name.parse()
                .map_err(|_| WorkspaceError::InvalidEngagement)?,
            runtime.manifest.artifact.reference.clone(),
            runtime.pass.digest.clone(),
        );
        let receipt = coordination::reserve_demo(
            &self.path,
            &self.root,
            &binding.workspace_id,
            &manifest,
            self.intent
                .as_ref()
                .and_then(|intent| intent.coordination.clone()),
            hook,
        )?;
        if self
            .intent
            .as_ref()
            .is_some_and(|intent| intent.coordination.is_none())
        {
            self.intent.as_mut().expect("setup intent").coordination = Some(receipt.clone());
            self.save(false, "coordination_receipt", hook)?;
        }
        coordination::provision_demo(
            &self.path,
            &self.root,
            &binding.workspace_id,
            &manifest,
            &receipt,
            hook,
        )?;
        self.current()?;
        if self.confirm_active()? {
            let guide = managed_guide::install(&self.root)?;
            self.current()?;
            return Ok(guide);
        }
        let guide = managed_guide::install(&self.root)?;
        self.current()?;
        publish_same(
            &self.root,
            CONFIG,
            &self.intent.as_ref().expect("setup intent").config,
            false,
            "config_flush",
            hook,
        )?;
        hook("config")?;
        self.current()?;
        publish_same(
            &self.state,
            &key(
                &self.path,
                &self.intent.as_ref().expect("setup intent").config,
            ),
            &encode(&binding)?,
            true,
            "binding_flush",
            hook,
        )?;
        hook("binding")?;
        self.current()?;
        Ok(guide)
    }

    pub fn confirm_active(&self) -> Result<bool, WorkspaceError> {
        self.confirm_active_with(&mut |_| Ok(()))
    }

    fn confirm_active_with(
        &self,
        hook: &mut impl FnMut(&str) -> io::Result<()>,
    ) -> Result<bool, WorkspaceError> {
        if !self.active()? {
            return Ok(false);
        }
        let intent = self.intent.as_ref().expect("setup intent");
        nofollow_file(&self.state, &key(&self.path, &intent.config))?.sync_all()?;
        hook("binding_confirm_file")?;
        rfs::fsync(&self.state).map_err(io::Error::from)?;
        hook("binding_confirm_state")?;
        self.current()?;
        Ok(true)
    }

    fn home_name(&self) -> String {
        format!(
            "demo-runtime-{}",
            self.intent.as_ref().expect("setup intent").attempt
        )
    }

    fn save(
        &self,
        exclusive: bool,
        stage: &str,
        hook: &mut impl FnMut(&str) -> io::Result<()>,
    ) -> Result<(), WorkspaceError> {
        atomic_write_with(
            &self.state,
            &demo_key(&self.path),
            &encode(self.intent.as_ref().expect("setup intent"))?,
            exclusive,
            stage,
            hook,
        )?;
        Ok(())
    }

    fn current(&self) -> Result<(), WorkspaceError> {
        let path = open_dir(&self.path).map_err(|_| WorkspaceError::Unbound)?;
        let state = state_dir_with(&self.state_path, false, &mut |_| Ok(()))?;
        if DirectoryIdentity::read(&path)? != DirectoryIdentity::read(&self.root)?
            || DirectoryIdentity::read(&state)? != DirectoryIdentity::read(&self.state)?
        {
            return Err(WorkspaceError::Unbound);
        }
        independent_state(&self.root, &self.state)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DemoPublishError {
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),
    #[error(transparent)]
    Guide(#[from] managed_guide::Error),
}

impl From<io::Error> for DemoPublishError {
    fn from(error: io::Error) -> Self {
        Self::Workspace(error.into())
    }
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, WorkspaceError> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() as u64 > LIMIT {
        return Err(WorkspaceError::InvalidEngagement);
    }
    Ok(bytes)
}

fn open_private_dir(parent: &File, name: &str) -> io::Result<File> {
    let dir = File::from(rfs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let stat = rfs::fstat(&dir)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err(io::Error::other("unsafe demo runtime directory"));
    }
    Ok(dir)
}

fn same_lease(dir: &File, expected: DirectoryIdentity) -> io::Result<File> {
    let lease = private_lock(dir, "supervisor.lease", false)?;
    if DirectoryIdentity::read(&lease)? != expected {
        return Err(io::Error::other("demo supervisor lease changed"));
    }
    Ok(lease)
}

fn verify_named_dir(parent: &File, name: &str, dir: &File) -> io::Result<()> {
    let named = rfs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    let opened = rfs::fstat(dir)?;
    if rfs::FileType::from_raw_mode(named.st_mode) != rfs::FileType::Directory
        || named.st_dev != opened.st_dev
        || named.st_ino != opened.st_ino
    {
        return Err(io::Error::other("demo runtime directory changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::runtime_authority_tests::{DECLARATION, runtime_for};
    use std::{
        collections::BTreeSet,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    const ENGAGEMENT: &str = "demo";

    fn authority(control: DemoControl) -> Authority {
        Authority {
            verifier_runtime: [(ENGAGEMENT.to_owned(), runtime_for(DECLARATION))].into(),
            demo: Some(control),
            ..Authority::default()
        }
    }

    fn empty() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("workspace");
        let state = temp.path().join("state");
        fs::create_dir(&state).unwrap();
        create_demo_root(&root).unwrap();
        (temp, root, state)
    }

    fn prepared() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        PathBuf,
        DemoControl,
        DemoWorkspace,
    ) {
        let (temp, root, state) = empty();
        let mut demo = check_demo_root(&root, &state).unwrap();
        let home = demo.reserve().unwrap();
        let control = DemoControl {
            socket: temp.path().join("control.sock"),
            expires: 4_102_444_800,
            token: Uuid::new_v4(),
        };
        demo.prepare(ENGAGEMENT, DECLARATION, authority(control.clone()))
            .unwrap();
        (temp, root, state, home, control, demo)
    }

    fn coordination_stages(root: &Path) -> Vec<PathBuf> {
        fs::read_dir(root)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path();
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".scourge-demo-")
                    .then_some(path)
            })
            .collect()
    }

    #[test]
    fn interrupted_intent_and_prepared_receipts_are_idempotent() {
        for stage in ["intent", "lease_created", "lease"] {
            let (_temp, root, state) = empty();
            let mut demo = check_demo_root(&root, &state).unwrap();
            let failure = demo.reserve_with(&mut |point| {
                if point == stage {
                    Err(io::Error::other("injected intent interruption"))
                } else {
                    Ok(())
                }
            });
            assert!(failure.is_err(), "{stage}");
            drop(demo);

            let mut retry = check_demo_root(&root, &state).unwrap();
            retry.reset().unwrap();
            retry.reserve().unwrap();
            let control = DemoControl {
                socket: state.join("control.sock"),
                expires: 4_102_444_800,
                token: Uuid::new_v4(),
            };
            retry
                .prepare(ENGAGEMENT, DECLARATION, authority(control))
                .unwrap();
            retry.publish(ENGAGEMENT).unwrap();
            assert!(select(&root, Some(&root), &state).is_ok(), "{stage}");
        }

        let (_temp, root, state) = empty();
        let mut demo = check_demo_root(&root, &state).unwrap();
        demo.reserve().unwrap();
        let control = DemoControl {
            socket: state.join("control.sock"),
            expires: 4_102_444_800,
            token: Uuid::new_v4(),
        };
        assert!(
            demo.prepare_with(
                ENGAGEMENT,
                DECLARATION,
                authority(control),
                &mut |point| if point == "prepared" {
                    Err(io::Error::other("injected prepared interruption"))
                } else {
                    Ok(())
                },
            )
            .is_err()
        );
        drop(demo);
        let mut retry = check_demo_root(&root, &state).unwrap();
        assert!(retry.authority().is_some());
        retry.publish(ENGAGEMENT).unwrap();
        assert!(select(&root, Some(&root), &state).is_ok());
    }

    #[test]
    fn each_publication_boundary_recovers_from_the_same_private_intent() {
        for stage in [
            "demo_directories_checked",
            "coordination_created",
            "coordination_receipt",
            "coordination_staged",
            "coordination_before_rename",
            "coordination_flush",
            "config_flush",
            "config",
            "binding_flush",
            "binding",
        ] {
            let (_temp, root, state, _home, _control, mut demo) = prepared();
            let mut injected = false;
            let failure = demo.publish_with(ENGAGEMENT, &mut |point| {
                if point == stage && !injected {
                    injected = true;
                    Err(io::Error::other("injected publication interruption"))
                } else {
                    Ok(())
                }
            });
            assert!(failure.is_err(), "{stage}");
            demo.publish(ENGAGEMENT).unwrap();
            let bound = select(&root, Some(&root), &state).unwrap();
            assert!(bound.open_coordination().is_ok(), "{stage}");
        }
    }

    #[test]
    fn rename_and_symlink_substitution_never_receive_publication() {
        for stage in [
            "demo_directories_checked",
            "coordination_created",
            "coordination_staged",
            "config",
            "binding",
        ] {
            let (temp, root, state, _home, _control, mut demo) = prepared();
            let original = temp.path().join(format!("original-{stage}"));
            let foreign = temp.path().join(format!("foreign-{stage}"));
            fs::create_dir(&foreign).unwrap();
            fs::write(foreign.join("sentinel"), b"foreign").unwrap();
            let mut substituted = false;
            let failure = demo.publish_with(ENGAGEMENT, &mut |point| {
                if point == stage && !substituted {
                    substituted = true;
                    fs::rename(&root, &original)?;
                    symlink(&foreign, &root)?;
                }
                Ok(())
            });
            assert!(failure.is_err(), "{stage}");
            assert_eq!(fs::read(foreign.join("sentinel")).unwrap(), b"foreign");
            assert_eq!(fs::read_dir(&foreign).unwrap().count(), 1, "{stage}");
            assert!(select(&foreign, Some(&root), &state).is_err(), "{stage}");
        }
    }

    #[test]
    fn final_binding_rejects_a_same_path_replacement_inode() {
        let (temp, root, state, _home, _control, mut demo) = prepared();
        demo.publish(ENGAGEMENT).unwrap();
        let config = fs::read(root.join(CONFIG)).unwrap();
        let original = temp.path().join("original-workspace");
        fs::rename(&root, &original).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join(CONFIG), config).unwrap();
        assert!(select(&root, Some(&root), &state).is_err());
        assert!(select(&original, Some(&original), &state).is_err());
    }

    #[test]
    fn ordinary_workspace_collision_is_rejected_without_creating_demo_state() {
        let (_temp, root, state) = empty();
        init(&root, &state, ENGAGEMENT, DECLARATION, Authority::default()).unwrap();
        let state_dir = state.join("scourge");
        let before: BTreeSet<_> = fs::read_dir(&state_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(check_demo_root(&root, &state).is_err());
        let after: BTreeSet<_> = fs::read_dir(&state_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(after, before);
    }

    #[test]
    fn confirmed_dead_runtime_retires_without_removing_archive_state() {
        let (_temp, root, state, _home, control, mut demo) = prepared();
        demo.publish(ENGAGEMENT).unwrap();
        assert!(demo.retire().is_ok());
        assert!(demo.retired());
        assert!(demo.retire().is_ok());
        assert!(demo_pending(&root, &state, &control).is_none());
        let archived = select(&root, Some(&root), &state).unwrap();
        assert!(archived.open_coordination().is_ok());
    }

    #[test]
    fn live_unreachable_supervisor_cannot_be_retired() {
        let (_temp, root, state, home, control, mut demo) = prepared();
        let _live_lease = demo_supervisor_lease(&home).unwrap();
        demo.publish(ENGAGEMENT).unwrap();
        assert!(demo.retire().is_err());
        assert!(!demo.retired());
        assert!(demo_pending(&root, &state, &control).is_some());
        let committed = select(&root, Some(&root), &state).unwrap();
        assert!(committed.open_coordination().is_ok());
    }

    #[test]
    fn lexical_aliases_share_one_demo_binding_and_control_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        fs::create_dir(&state).unwrap();
        let canonical = temp.path().join("nested").join("workspace");
        let repeated = PathBuf::from(format!(
            "//{}//nested///workspace//",
            temp.path().display().to_string().trim_start_matches('/')
        ));
        create_demo_root(&repeated).unwrap();
        let mut demo = check_demo_root(&repeated, &state).unwrap();
        assert_eq!(demo.root(), canonical);
        demo.reserve().unwrap();
        let control = DemoControl {
            socket: state.join("control.sock"),
            expires: 4_102_444_800,
            token: Uuid::new_v4(),
        };
        demo.prepare(ENGAGEMENT, DECLARATION, authority(control.clone()))
            .unwrap();
        demo.publish(ENGAGEMENT).unwrap();
        let selected = select(&canonical, Some(&repeated), &state).unwrap();
        assert_eq!(selected.root, canonical);
        assert_eq!(
            demo_fallback_control(&repeated, &state),
            Some((canonical, control))
        );
    }

    #[test]
    fn reset_recovers_around_the_durable_abandonment_receipt() {
        for stage in [
            "reset_lease",
            "reset_coordination",
            "abandonment_flush",
            "abandonment",
            "reset",
        ] {
            let (_temp, root, state) = empty();
            let mut demo = check_demo_root(&root, &state).unwrap();
            let abandoned = demo.reserve().unwrap();
            let attempt = demo.intent.as_ref().unwrap().attempt;
            let home_identity = DirectoryIdentity::read(&open_dir(&abandoned).unwrap()).unwrap();
            let lease_identity = demo.intent.as_ref().unwrap().lease.unwrap();
            let mut injected = false;
            assert!(
                demo.reset_with(&mut |point| {
                    if point == stage && !injected {
                        injected = true;
                        Err(io::Error::other("injected reset interruption"))
                    } else {
                        Ok(())
                    }
                })
                .is_err(),
                "{stage}"
            );
            drop(demo);
            let mut retry = check_demo_root(&root, &state)
                .unwrap_or_else(|error| panic!("{stage}: failed to reopen: {error:?}"));
            retry.reset().unwrap();
            let next = retry.reserve().unwrap();
            assert_ne!(next, abandoned, "{stage}");
            assert!(abandoned.join("supervisor.lease").is_file(), "{stage}");
            assert!(
                retry
                    .intent
                    .as_ref()
                    .unwrap()
                    .abandoned
                    .iter()
                    .any(|receipt| {
                        receipt.attempt == attempt
                            && receipt.home.name == abandoned.file_name().unwrap().to_string_lossy()
                            && receipt.home.identity == home_identity
                            && receipt.lease == lease_identity
                    }),
                "{stage}"
            );
        }
    }

    #[test]
    fn receipted_missing_lease_is_never_relaxed() {
        let (_temp, root, state) = empty();
        let mut demo = check_demo_root(&root, &state).unwrap();
        let home = demo.reserve().unwrap();
        fs::remove_file(home.join("supervisor.lease")).unwrap();
        fs::write(home.join("foreign"), b"operator bytes").unwrap();
        assert!(demo.reset().is_err());
        assert_eq!(fs::read(home.join("foreign")).unwrap(), b"operator bytes");
    }

    #[test]
    fn unreceipted_runtime_attempt_is_preserved_and_rotated_before_supervisor_start() {
        let (_temp, root, state) = empty();
        let mut demo = check_demo_root(&root, &state).unwrap();
        let old_attempt = demo
            .reserve_with(&mut |point| {
                if point == "lease_created" {
                    Err(io::Error::other("crash before lease receipt"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(
            old_attempt.code(),
            crate::wire::ErrorCode::DependencyUnavailable
        );
        assert!(demo.authority().is_none());
        let orphan = state.join("scourge").join(format!(
            "demo-runtime-{}",
            demo.intent.as_ref().unwrap().attempt
        ));
        fs::write(orphan.join("foreign"), b"preserve me").unwrap();
        drop(demo);

        let mut retry = check_demo_root(&root, &state).unwrap();
        assert!(retry.authority().is_none());
        retry.reset().unwrap();
        let next = retry.reserve().unwrap();
        assert_ne!(next, orphan);
        assert_eq!(fs::read(orphan.join("foreign")).unwrap(), b"preserve me");
        assert!(orphan.join("supervisor.lease").is_file());
    }

    #[test]
    fn unreceipted_coordination_stage_is_preserved_and_retry_uses_a_fresh_name() {
        let (_temp, root, _state, _home, _control, mut demo) = prepared();
        assert!(
            demo.publish_with(
                ENGAGEMENT,
                &mut |point| if point == "coordination_created" {
                    Err(io::Error::other("crash before coordination receipt"))
                } else {
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(demo.intent.as_ref().unwrap().coordination.is_none());
        let stages = coordination_stages(&root);
        assert_eq!(stages.len(), 1);
        let orphan = stages[0].clone();
        fs::write(orphan.join("foreign"), b"preserve me").unwrap();
        demo.publish(ENGAGEMENT).unwrap();
        assert_eq!(fs::read(orphan.join("foreign")).unwrap(), b"preserve me");
        assert!(root.join(".scourge").is_dir());
        assert_ne!(
            demo.intent
                .as_ref()
                .unwrap()
                .coordination
                .as_ref()
                .unwrap()
                .name,
            orphan.file_name().unwrap().to_string_lossy()
        );
    }

    #[test]
    #[ignore = "spawns a real orphan helper; run alone to avoid fork inheriting parallel test locks"]
    fn sigkill_orphan_helper_writes_only_into_the_receipted_abandoned_attempt() {
        let (_temp, root, state) = empty();
        let mut demo = check_demo_root(&root, &state).unwrap();
        let abandoned = demo.reserve().unwrap();
        let attempt = demo.intent.as_ref().unwrap().attempt;
        let script = r#"
            (
                printf ready > "$1/helper-ready"
                while [ ! -e "$1/release-helper" ]; do sleep 0.01; done
                mkdir -p "$1/late/nested"
                printf late > "$1/late/nested/leaf"
                printf done > "$1/helper-done"
            ) &
            wait
        "#;
        let mut parent = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .arg("orphan-helper")
            .arg(&abandoned)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_file(&abandoned.join("helper-ready"));
        parent.kill().unwrap();
        let status = parent.wait().unwrap();
        assert_eq!(status.signal(), Some(9));

        drop(demo);
        let mut retry = check_demo_root(&root, &state).unwrap();
        retry.reset().unwrap();
        let fresh = retry.reserve().unwrap();
        assert_ne!(fresh, abandoned);
        let receipt = retry
            .intent
            .as_ref()
            .unwrap()
            .abandoned
            .iter()
            .find(|receipt| receipt.attempt == attempt)
            .unwrap();
        assert_eq!(
            receipt.home.name,
            abandoned.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(
            receipt.home.identity,
            DirectoryIdentity::read(&open_dir(&abandoned).unwrap()).unwrap()
        );

        fs::write(abandoned.join("release-helper"), b"go").unwrap();
        wait_for_file(&abandoned.join("helper-done"));
        assert_eq!(
            fs::read(abandoned.join("late/nested/leaf")).unwrap(),
            b"late"
        );
        assert!(!fresh.join("late").exists());
    }

    fn wait_for_file(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn anchor_detects_config_and_state_loss_while_fallback_control_survives_config_loss() {
        let (temp, root, state, _home, control, mut demo) = prepared();
        demo.publish(ENGAGEMENT).unwrap();
        let mut anchor = demo_pending(&root, &state, &control).unwrap();
        assert!(anchor.current());
        assert!(anchor.activate());
        assert!(anchor.healthy());
        let config = fs::read(root.join(CONFIG)).unwrap();
        fs::rename(root.join(CONFIG), temp.path().join("original-config")).unwrap();
        fs::write(root.join(CONFIG), config).unwrap();
        assert!(anchor.current());
        assert!(!anchor.healthy());
        assert_eq!(
            demo_fallback_control(&root, &state),
            Some((root.clone(), control))
        );

        let original = temp.path().join("original-state");
        fs::rename(state.join("scourge"), &original).unwrap();
        fs::create_dir(state.join("scourge")).unwrap();
        fs::set_permissions(state.join("scourge"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!anchor.current());
    }

    #[test]
    fn ordinary_init_and_demo_publish_only_one_claim() {
        let (_temp, root, state) = empty();
        let demo = check_demo_root(&root, &state)
            .unwrap_or_else(|error| panic!("initial demo claim failed: {error:?}"));
        assert!(
            super::super::init(&root, &state, ENGAGEMENT, DECLARATION, Authority::default(),)
                .is_err()
        );
        drop(demo);

        let (claimed_tx, claimed_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let worker_root = root.clone();
        let worker_state = state.clone();
        let worker = thread::spawn(move || {
            super::super::init_with_hook(
                &worker_root,
                &worker_state,
                ENGAGEMENT,
                DECLARATION,
                Authority::default(),
                |stage| {
                    if stage == "claim" {
                        claimed_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                    }
                    Ok(())
                },
            )
        });
        claimed_rx
            .recv()
            .unwrap_or_else(|error| panic!("ordinary init exited before claim hook: {error}"));
        assert!(check_demo_root(&root, &state).is_err());
        release_tx
            .send(())
            .unwrap_or_else(|error| panic!("ordinary init dropped claim receiver: {error}"));
        assert!(
            worker
                .join()
                .unwrap_or_else(|_| panic!("ordinary init worker panicked"))
                .is_ok()
        );
        let state_dir = state.join("scourge");
        assert!(fs::read_dir(state_dir).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("demo-runtime-")
        }));
    }

    #[test]
    fn coordination_stage_substitution_and_published_seed_changes_refuse() {
        let (temp, root, _state, _home, _control, mut demo) = prepared();
        let moved = temp.path().join("original-stage");
        let mut replaced = None;
        let failure = demo.publish_with(ENGAGEMENT, &mut |point| {
            if point == "coordination_before_rename" {
                let stage = coordination_stages(&root).pop().unwrap();
                let name = stage.file_name().unwrap().to_owned();
                fs::rename(root.join(&stage), &moved)?;
                fs::create_dir(root.join(&name))?;
                fs::set_permissions(root.join(&name), fs::Permissions::from_mode(0o700))?;
                fs::write(root.join(&name).join("sentinel"), b"foreign")?;
                replaced = Some(root.join(name));
            }
            Ok(())
        });
        assert!(failure.is_err());
        assert_eq!(
            fs::read(replaced.unwrap().join("sentinel")).unwrap(),
            b"foreign"
        );

        let (_temp, root, _state, _home, _control, mut demo) = prepared();
        demo.publish(ENGAGEMENT).unwrap();
        let workspace = demo.intent.as_ref().unwrap().workspace_id.to_string();
        let mut store = crate::store::Store::open_workspace(
            &root.join(".scourge").join("state.sqlite3"),
            &workspace,
        )
        .unwrap();
        store
            .register_workspace_engagements(None, ["foreign"].into_iter())
            .unwrap();
        drop(store);
        assert!(demo.publish(ENGAGEMENT).is_err());
    }

    #[test]
    fn binding_flush_failure_is_not_committed_until_durable_confirmation() {
        let (_temp, _root, _state, _home, _control, mut demo) = prepared();
        let mut injected = false;
        assert!(
            demo.publish_with(ENGAGEMENT, &mut |point| {
                if point == "binding_flush" && !injected {
                    injected = true;
                    Err(io::Error::other("injected binding directory fsync failure"))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert!(
            demo.confirm_active_with(&mut |point| if point == "binding_confirm_state" {
                Err(io::Error::other("injected confirmation fsync failure"))
            } else {
                Ok(())
            })
            .is_err()
        );
        assert!(demo.confirm_active().unwrap());
    }
}
