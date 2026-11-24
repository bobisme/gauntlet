//! Coordination paths are local to the independently bound workspace.

use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};

use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags, Stat};
use uuid::Uuid;

use super::{WorkspaceError, nofollow_file, open_dir};
use crate::store::{Store, read::ReadStore};

const DIRECTORY: &str = ".scourge";
const DATABASE: &str = "state.sqlite3";

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

pub(super) fn provision<'a>(
    root: &Path,
    root_dir: &File,
    workspace: &str,
    names: impl Iterator<Item = &'a String> + Clone,
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
            if files.install(workspace, names.clone())? {
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
