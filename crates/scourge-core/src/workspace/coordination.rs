//! Coordination paths are local to the independently bound workspace.

use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags, Stat};
use uuid::Uuid;

use super::{
    InitialManifest, WorkspaceError,
    demo::{DirectoryIdentity, NamedDirectoryIdentity},
    nofollow_file, open_dir,
};
use crate::store::{Store, read::ReadStore};

const DIRECTORY: &str = ".scourge";
const DATABASE: &str = "state.sqlite3";
const DEMO_OWNER: &str = "demo-owner";

fn new_demo_stage(workspace: &str) -> String {
    format!(".scourge-demo-{workspace}-{}", Uuid::new_v4())
}

fn valid_demo_stage(workspace: &str, name: &str) -> bool {
    name.strip_prefix(&format!(".scourge-demo-{workspace}-"))
        .is_some_and(|suffix| Uuid::parse_str(suffix).is_ok())
}

fn demo_open(root: &File, name: &str) -> io::Result<File> {
    let file = File::from(rfs::openat(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    check_private(&rfs::fstat(&file)?)?;
    Ok(file)
}

fn demo_seed(workspace: &str, manifest: &InitialManifest) -> io::Result<Vec<u8>> {
    serde_json::to_vec(&(workspace, &manifest.0, &manifest.1, &manifest.2))
        .map_err(io::Error::other)
}

fn demo_owned(directory: &File, workspace: &str, manifest: &InitialManifest) -> io::Result<()> {
    let file = nofollow_file(directory, DEMO_OWNER)?;
    check_regular(&rfs::fstat(&file)?)?;
    let mut contents = Vec::new();
    file.take(4096).read_to_end(&mut contents)?;
    if contents != demo_seed(workspace, manifest)? {
        return Err(io::Error::other("demo coordination ownership changed"));
    }
    Ok(())
}

fn demo_named(root: &File, name: &str, opened: &File) -> io::Result<()> {
    let named = rfs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW)?;
    check_private(&named)?;
    same_file(&named, &rfs::fstat(opened)?)
}

fn verify_demo_published(
    root_path: &Path,
    root: &File,
    expected: DirectoryIdentity,
    workspace: &str,
    manifest: &InitialManifest,
) -> Result<(), WorkspaceError> {
    let directory = demo_open(root, DIRECTORY)?;
    if DirectoryIdentity::read(&directory)? != expected {
        return Err(WorkspaceError::CoordinationInvalid);
    }
    demo_named(root, DIRECTORY, &directory).map_err(read_error)?;
    demo_owned(&directory, workspace, manifest).map_err(read_error)?;
    let files = Files::open(root_path, root).map_err(read_error)?;
    let identity = files.file(DATABASE).map_err(read_error)?;
    files
        .verify_named(DATABASE, &identity)
        .map_err(read_error)?;
    let store = ReadStore::open(&files.path.join(DATABASE))?;
    files
        .verify_named(DATABASE, &identity)
        .map_err(read_error)?;
    store.verify_demo_seed(workspace, &manifest.0, &manifest.1, &manifest.2)?;
    files
        .verify_named(DATABASE, &identity)
        .map_err(read_error)?;
    Ok(())
}

/// Reserve or reopen the exact intent-owned staging inode before any cleanup.
/// An existing name without the durable inode receipt is never adopted.
pub(super) fn reserve_demo(
    root_path: &Path,
    root: &File,
    workspace: &str,
    manifest: &InitialManifest,
    expected: Option<NamedDirectoryIdentity>,
    hook: &mut impl FnMut(&str) -> io::Result<()>,
) -> Result<NamedDirectoryIdentity, WorkspaceError> {
    if demo_open_optional(root, DIRECTORY)?.is_some() {
        let expected = expected.ok_or(WorkspaceError::CoordinationInvalid)?;
        if !valid_demo_stage(workspace, &expected.name) {
            return Err(WorkspaceError::CoordinationInvalid);
        }
        verify_demo_published(root_path, root, expected.identity, workspace, manifest)?;
        return Ok(expected);
    }
    match expected {
        Some(expected) => {
            if !valid_demo_stage(workspace, &expected.name) {
                return Err(WorkspaceError::CoordinationInvalid);
            }
            let staged = demo_open(root, &expected.name).map_err(read_error)?;
            demo_named(root, &expected.name, &staged).map_err(read_error)?;
            if DirectoryIdentity::read(&staged)? != expected.identity {
                return Err(WorkspaceError::CoordinationInvalid);
            }
            Ok(expected)
        }
        None => {
            for _ in 0..8 {
                let name = new_demo_stage(workspace);
                match rfs::mkdirat(root, name.as_str(), Mode::from_raw_mode(0o700)) {
                    Ok(()) => {
                        let staged = demo_open(root, &name).map_err(read_error)?;
                        demo_named(root, &name, &staged).map_err(read_error)?;
                        let receipt = NamedDirectoryIdentity {
                            name,
                            identity: DirectoryIdentity::read(&staged)?,
                        };
                        hook("coordination_created")?;
                        return Ok(receipt);
                    }
                    Err(rustix::io::Errno::EXIST) => continue,
                    Err(error) => return Err(io::Error::from(error).into()),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate unique demo coordination stage",
            )
            .into())
        }
    }
}

/// Initialize SQLite in a private scratch directory. All publication into the
/// workspace uses the original directory descriptor, even during a rename.
pub(super) fn provision_demo(
    root_path: &Path,
    root: &File,
    workspace: &str,
    manifest: &InitialManifest,
    expected: &NamedDirectoryIdentity,
    hook: &mut impl FnMut(&str) -> io::Result<()>,
) -> Result<(), WorkspaceError> {
    if !valid_demo_stage(workspace, &expected.name) {
        return Err(WorkspaceError::CoordinationInvalid);
    }
    let stage = &expected.name;
    if demo_open_optional(root, DIRECTORY)?.is_some() {
        verify_demo_published(root_path, root, expected.identity, workspace, manifest)?;
        hook("coordination_flush")?;
        let directory = demo_open(root, DIRECTORY)?;
        rfs::fsync(&directory).map_err(io::Error::from)?;
        rfs::fsync(root).map_err(io::Error::from)?;
        return Ok(());
    }
    let staged_dir = demo_open(root, stage)?;
    demo_named(root, stage, &staged_dir).map_err(read_error)?;
    if DirectoryIdentity::read(&staged_dir)? != expected.identity {
        return Err(WorkspaceError::CoordinationInvalid);
    }
    // Before the final rename only known setup files can exist here. Clear
    // any interrupted staged database and materialize it from the same intent.
    demo_unlink_staged(&staged_dir)?;
    write_demo_file(
        &staged_dir,
        DEMO_OWNER,
        demo_seed(workspace, manifest)?.as_slice(),
    )?;
    hook("coordination_staged")?;
    let scratch = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")?;
    let staged = scratch.path().join(DATABASE);
    let mut store = Store::open(&staged)?;
    store.register_workspace_engagements(Some(workspace), std::iter::once(manifest.0.as_str()))?;
    store.append_manifest(&manifest.0, &manifest.1, &manifest.2)?;
    store.checkpoint_new_file()?;
    drop(store);
    let staged_file = File::open(&staged)?;
    write_demo_file(&staged_dir, DATABASE, staged_file)?;
    rfs::fsync(&staged_dir).map_err(io::Error::from)?;
    hook("coordination_before_rename")?;
    demo_named(root, stage, &staged_dir).map_err(read_error)?;
    rfs::renameat_with(
        root,
        stage.as_str(),
        root,
        DIRECTORY,
        rfs::RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)?;
    demo_named(root, DIRECTORY, &staged_dir).map_err(read_error)?;
    hook("coordination_flush")?;
    rfs::fsync(root).map_err(io::Error::from)?;
    verify_demo_published(root_path, root, expected.identity, workspace, manifest)?;
    Ok(())
}

fn write_demo_file(dir: &File, name: &str, mut bytes: impl Read) -> io::Result<()> {
    let mut file = File::from(rfs::openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    io::copy(&mut bytes, &mut file)?;
    file.flush()?;
    file.sync_all()
}

fn demo_open_optional(root: &File, name: &str) -> io::Result<Option<File>> {
    match demo_open(root, name) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn demo_unlink_staged(dir: &File) -> io::Result<()> {
    for entry in rfs::Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if !matches!(
            name.to_bytes(),
            b"." | b".." | b"demo-owner" | b"state.sqlite3"
        ) {
            return Err(io::Error::other(
                "demo coordination contains unrelated entries",
            ));
        }
    }
    for name in [DATABASE, DEMO_OWNER] {
        match rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => {
                check_regular(&metadata)?;
                rfs::unlinkat(dir, name, AtFlags::empty())?;
            }
            Err(rustix::io::Errno::NOENT) => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(super) fn discard_demo(
    root: &File,
    workspace: &str,
    expected: Option<NamedDirectoryIdentity>,
) -> Result<(), WorkspaceError> {
    let Some(expected) = expected else {
        return if demo_open_optional(root, DIRECTORY)?.is_none() {
            Ok(())
        } else {
            Err(WorkspaceError::CoordinationInvalid)
        };
    };
    if !valid_demo_stage(workspace, &expected.name) {
        return Err(WorkspaceError::CoordinationInvalid);
    }
    let stage = expected.name.clone();
    if let Some(published) = demo_open_optional(root, DIRECTORY)? {
        if DirectoryIdentity::read(&published)? != expected.identity {
            return Err(WorkspaceError::CoordinationInvalid);
        }
        demo_named(root, DIRECTORY, &published).map_err(read_error)?;
        // Move back to the durable intent's private staging name. If
        // cleanup is interrupted, the same owned staging path can be retried.
        rfs::renameat_with(
            root,
            DIRECTORY,
            root,
            stage.as_str(),
            rfs::RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)?;
        rfs::fsync(root).map_err(io::Error::from)?;
    }
    if let Some(staged) = demo_open_optional(root, &stage)? {
        if DirectoryIdentity::read(&staged)? != expected.identity {
            return Err(WorkspaceError::CoordinationInvalid);
        }
        demo_named(root, &stage, &staged).map_err(read_error)?;
        demo_unlink_staged(&staged)?;
        demo_named(root, &stage, &staged).map_err(read_error)?;
        rfs::unlinkat(root, stage.as_str(), AtFlags::REMOVEDIR).map_err(io::Error::from)?;
        rfs::fsync(root).map_err(io::Error::from)?;
    }
    Ok(())
}

struct Files {
    dir: File,
    path: PathBuf,
}

impl Files {
    fn open(root: &Path, root_dir: &File) -> io::Result<Self> {
        let dir = File::from(rfs::openat(
            root_dir,
            DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let stat = rfs::fstat(&dir)?;
        check_private(&stat)?;
        Ok(Self {
            dir,
            path: root.join(DIRECTORY),
        })
    }

    fn file(&self, name: &str) -> io::Result<File> {
        let stat = rfs::statat(&self.dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
        check_regular(&stat)?;
        let file = nofollow_file(&self.dir, name)?;
        let opened = rfs::fstat(&file)?;
        check_regular(&opened)?;
        same_file(&stat, &opened)?;
        Ok(file)
    }

    fn verify_named(&self, name: &str, file: &File) -> io::Result<()> {
        let current = open_dir(&self.path)?;
        same_file(&rfs::fstat(&self.dir)?, &rfs::fstat(&current)?)?;
        let named = rfs::statat(&current, name, AtFlags::SYMLINK_NOFOLLOW)?;
        check_regular(&named)?;
        same_file(&rfs::fstat(file)?, &named)
    }

    fn check_sidecars(&self) -> io::Result<()> {
        for name in [
            "state.sqlite3-wal",
            "state.sqlite3-shm",
            "state.sqlite3-journal",
        ] {
            match rfs::statat(&self.dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => check_regular(&stat)?,
                Err(rustix::io::Errno::NOENT) => (),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn install(
        &self,
        workspace: &str,
        names: impl Iterator<Item = impl AsRef<str>>,
        manifest: Option<&InitialManifest>,
    ) -> Result<bool, WorkspaceError> {
        let name = format!(".state-{}.tmp", Uuid::new_v4());
        let file = File::from(
            rfs::openat(
                &self.dir,
                name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(io::Error::from)?,
        );
        let result = (|| {
            self.verify_named(&name, &file)?;
            let mut store = Store::open(self.path.join(&name))?;
            let names: Vec<_> = names.collect();
            store
                .register_workspace_engagements(Some(workspace), names.iter().map(AsRef::as_ref))?;
            if let Some((engagement, artifact, digest)) = manifest {
                store.append_manifest(engagement, artifact, digest)?;
            }
            store.checkpoint_new_file()?;
            drop(store);
            file.sync_all()?;
            self.verify_named(&name, &file)?;
            match rfs::renameat_with(
                &self.dir,
                name.as_str(),
                &self.dir,
                DATABASE,
                rfs::RenameFlags::NOREPLACE,
            ) {
                Ok(()) => Ok(true),
                Err(rustix::io::Errno::EXIST) => Ok(false),
                Err(error) => Err(io::Error::from(error).into()),
            }
        })();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = rfs::unlinkat(
                &self.dir,
                format!("{name}{suffix}").as_str(),
                AtFlags::empty(),
            );
        }
        result
    }
}

fn check_private(stat: &Stat) -> io::Result<()> {
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err(io::Error::other(
            "unsafe coordination path ownership or permissions",
        ));
    }
    Ok(())
}

fn check_regular(stat: &Stat) -> io::Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
        return Err(io::Error::other(
            "coordination path is not a private regular file",
        ));
    }
    check_private(stat)
}

fn same_file(expected: &Stat, current: &Stat) -> io::Result<()> {
    if (expected.st_dev, expected.st_ino) != (current.st_dev, current.st_ino) {
        return Err(io::Error::other("coordination path changed"));
    }
    Ok(())
}

fn read_error(error: io::Error) -> WorkspaceError {
    if error.kind() == io::ErrorKind::NotFound {
        WorkspaceError::CoordinationUnavailable
    } else {
        WorkspaceError::CoordinationInvalid
    }
}

pub(super) fn open(root: &Path, workspace: &str) -> Result<ReadStore, WorkspaceError> {
    let root_dir = open_dir(root).map_err(read_error)?;
    let files = Files::open(root, &root_dir).map_err(read_error)?;
    let identity = files.file(DATABASE).map_err(read_error)?;
    files.check_sidecars().map_err(read_error)?;
    files
        .verify_named(DATABASE, &identity)
        .map_err(read_error)?;
    let store = ReadStore::open(&files.path.join(DATABASE))?;
    store.verify_workspace(workspace)?;
    files
        .verify_named(DATABASE, &identity)
        .map_err(read_error)?;
    Ok(store)
}

pub(super) fn open_write(root: &Path, workspace: &str) -> Result<Store, WorkspaceError> {
    let root_dir = open_dir(root).map_err(read_error)?;
    let files = Files::open(root, &root_dir).map_err(read_error)?;
    let identity = files.file(DATABASE).map_err(read_error)?;
    files.check_sidecars().map_err(read_error)?;
    files
        .verify_named(DATABASE, &identity)
        .map_err(read_error)?;
    let store = Store::open_workspace(&files.path.join(DATABASE), workspace)?;
    files
        .verify_named(DATABASE, &identity)
        .map_err(read_error)?;
    Ok(store)
}

pub(super) fn provision<'a>(
    root: &Path,
    root_dir: &File,
    workspace: &str,
    names: impl Iterator<Item = &'a String> + Clone,
    manifest: Option<&InitialManifest>,
    hook: &mut impl FnMut(&str) -> io::Result<()>,
) -> Result<(), WorkspaceError> {
    match rfs::mkdirat(root_dir, DIRECTORY, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => (),
        Err(error) => return Err(io::Error::from(error).into()),
    };
    let files = Files::open(root, root_dir).map_err(read_error)?;
    hook("coordination_parent_flush")?;
    rfs::fsync(root_dir).map_err(io::Error::from)?;
    match files.file(DATABASE) {
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if files.install(workspace, names.clone(), manifest)? {
                hook("coordination_flush")?;
                rfs::fsync(&files.dir).map_err(io::Error::from)?;
                return Ok(());
            }
        }
        Err(error) => return Err(read_error(error)),
    }
    let identity = files.file(DATABASE).map_err(read_error)?;
    files.check_sidecars().map_err(read_error)?;
    files
        .verify_named(DATABASE, &identity)
        .map_err(read_error)?;
    let mut store = Store::open_workspace(&files.path.join(DATABASE), workspace)?;
    files
        .verify_named(DATABASE, &identity)
        .map_err(read_error)?;
    store.register_workspace_engagements(None, names.map(String::as_str))?;
    hook("coordination_flush")?;
    rfs::fsync(&files.dir).map_err(io::Error::from)?;
    Ok(())
}
