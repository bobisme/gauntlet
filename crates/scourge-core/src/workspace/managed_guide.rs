//! Opt-in installation of the project guide after the workspace is bound.

use std::{
    fs::File,
    io::{self, Seek, Write},
    path::Path,
};

use rustix::fs::{self as rfs, FlockOperation, Mode, OFlags};
use rustix::process::{Gid, Uid};
use uuid::Uuid;

use super::{
    Authority, BoundWorkspace, LIMIT, WorkspaceError, atomic_write_with, init_with_hook,
    nofollow_file, read_limited,
};
use crate::canonical::Sha256Digest;

const FILE: &str = "AGENTS.md";
const MARKER_PREFIX: &[u8] = b"scourge:managed-";
const START: &str = "<!-- scourge:managed-start -->\n";
const END: &str = "<!-- scourge:managed-end -->\n";
const DIGEST: &str = "<!-- scourge:managed-sha256 ";
const BODY: &str = include_str!("managed-guide.md");
const MAX_ATTEMPTS: usize = 3;
const ACCESS_ACL: &str = "system.posix_acl_access";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Installed,
    Unchanged,
}

pub struct Receipt {
    pub status: Status,
    pub digest: Sha256Digest,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "AGENTS.md has ambiguous Scourge ownership markers. Review those markers before retrying."
    )]
    Ambiguous,
    #[error(
        "The Scourge guide block or its digest was edited in AGENTS.md. Review it before retrying."
    )]
    Edited,
    #[error(
        "AGENTS.md must be a regular file with a single link. Review the path before retrying."
    )]
    UnsafePath,
    #[error(
        "AGENTS.md changed during installation or another guide install is running. Retry init."
    )]
    Busy,
    #[error("AGENTS.md could not be durably updated. Review it before retrying init.")]
    Io(#[from] io::Error),
}

/// Commit the same binding as ordinary init, then opt into guide installation
/// through the directory handle that init already validated.
pub fn init(
    root: &Path,
    state: &Path,
    name: &str,
    declaration: &[u8],
    authority: Authority,
) -> Result<(BoundWorkspace, Result<Receipt, Error>), WorkspaceError> {
    let (bound, dir) = init_with_hook(root, state, name, declaration, authority, |_| Ok(()))?;
    Ok((bound, install(&dir)))
}

fn install(dir: &File) -> Result<Receipt, Error> {
    install_with(dir, &mut || Ok(()))
}

fn install_with(
    dir: &File,
    before_revalidate: &mut impl FnMut() -> io::Result<()>,
) -> Result<Receipt, Error> {
    match rfs::flock(dir, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => (),
        Err(rustix::io::Errno::WOULDBLOCK) => return Err(Error::Busy),
        Err(error) => return Err(io::Error::from(error).into()),
    }
    let digest = Sha256Digest::of(BODY.as_bytes());
    let block = format!("{START}{DIGEST}{} -->\n{BODY}{END}", digest.as_str());
    for _ in 0..MAX_ATTEMPTS {
        match install_attempt(dir, block.as_bytes(), before_revalidate) {
            Ok(status) => return Ok(Receipt { status, digest }),
            Err(Error::Busy) => (),
            Err(error) => return Err(error),
        }
    }
    Err(Error::Busy)
}

fn install_attempt(
    dir: &File,
    block: &[u8],
    before_revalidate: &mut impl FnMut() -> io::Result<()>,
) -> Result<Status, Error> {
    match nofollow_file(dir, FILE) {
        Ok(file) => install_in_existing(dir, file, block, before_revalidate),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match atomic_write_with(dir, FILE, block, true, "managed_guide_flush", &mut |_| {
                Ok(())
            }) {
                Ok(()) => Ok(Status::Installed),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(Error::Busy),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(open_error(error)),
    }
}

fn install_in_existing(
    dir: &File,
    file: File,
    block: &[u8],
    before_revalidate: &mut impl FnMut() -> io::Result<()>,
) -> Result<Status, Error> {
    let stat = regular_file(&file)?;
    let bytes = read_limited(file.try_clone()?)?;
    ensure_current(dir, &file, &stat)?;
    if has_unchanged_block(&bytes, block)? {
        file.sync_all()?;
        ensure_current(dir, &file, &stat)?;
        rfs::fsync(dir).map_err(io::Error::from)?;
        return Ok(Status::Unchanged);
    }

    let replacement = [bytes.as_slice(), b"\n\n", block].concat();
    if replacement.len() as u64 > LIMIT {
        return Err(io::Error::other("guide too large").into());
    }

    let temp = format!(".scourge-guide-{}.tmp", Uuid::new_v4());
    let mut staged = File::from(
        rfs::openat(
            dir,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(io::Error::from)?,
    );
    let result = (|| {
        staged.write_all(&replacement)?;
        preserve_metadata(&staged, &file, &stat)?;
        staged.sync_all()?;
        let staged_stat = regular_file(&staged)?;
        before_revalidate()?;
        ensure_current(dir, &file, &stat)?;
        let mut reader = file.try_clone()?;
        reader.rewind()?;
        if read_limited(reader)? != bytes {
            return Err(Error::Busy);
        }
        ensure_path(dir, temp.as_str(), &staged, &staged_stat)?;
        // This is optimistic concurrency with external editors. Rename has
        // no conditional-inode form. In particular, an uncooperative writer
        // can write after replacement through a descriptor for the old inode.
        ensure_current(dir, &file, &stat)?;
        rfs::renameat(dir, temp.as_str(), dir, FILE).map_err(io::Error::from)?;
        rfs::fsync(dir).map_err(io::Error::from)?;
        Ok(Status::Installed)
    })();
    if result.is_err()
        && let (Ok(descriptor), Ok(entry)) = (
            rfs::fstat(&staged),
            rfs::statat(dir, temp.as_str(), rfs::AtFlags::SYMLINK_NOFOLLOW),
        )
        && same_inode(&descriptor, &entry)
    {
        let _ = rfs::unlinkat(dir, temp.as_str(), rfs::AtFlags::empty());
    }
    result
}

fn preserve_metadata(staged: &File, original: &File, source: &rfs::Stat) -> Result<(), Error> {
    let stat = regular_file(staged)?;
    if stat.st_uid != source.st_uid || stat.st_gid != source.st_gid {
        rfs::fchown(
            staged,
            Some(Uid::from_raw(source.st_uid)),
            Some(Gid::from_raw(source.st_gid)),
        )
        .map_err(io::Error::from)?;
    }
    let mode = Mode::from_raw_mode(source.st_mode & 0o7777);
    rfs::fchmod(staged, mode).map_err(io::Error::from)?;
    preserve_access_acl(staged, original)?;
    let copied = regular_file(staged)?;
    if copied.st_mode != source.st_mode
        || copied.st_uid != source.st_uid
        || copied.st_gid != source.st_gid
    {
        return Err(io::Error::other("guide metadata could not be preserved").into());
    }
    Ok(())
}

fn preserve_access_acl(staged: &File, original: &File) -> io::Result<()> {
    match rfs::fgetxattr_query(original, ACCESS_ACL) {
        Ok(size) => {
            let mut bytes = vec![0; size];
            let actual = rfs::fgetxattr(original, ACCESS_ACL, bytes.as_mut_slice())?;
            rfs::fsetxattr(
                staged,
                ACCESS_ACL,
                &bytes[..actual],
                rfs::XattrFlags::empty(),
            )?;
        }
        Err(rustix::io::Errno::NODATA) => {
            // Do not keep an access ACL inherited from the parent directory.
            match rfs::fremovexattr(staged, ACCESS_ACL) {
                Ok(()) | Err(rustix::io::Errno::NODATA) => (),
                Err(error) => return Err(error.into()),
            }
        }
        Err(rustix::io::Errno::NOTSUP) => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn open_error(error: io::Error) -> Error {
    if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
        Error::UnsafePath
    } else {
        Error::Io(error)
    }
}

fn regular_file(file: &File) -> Result<rfs::Stat, Error> {
    let stat = rfs::fstat(file).map_err(io::Error::from)?;
    if rfs::FileType::from_raw_mode(stat.st_mode) != rfs::FileType::RegularFile
        || stat.st_nlink != 1
    {
        return Err(Error::UnsafePath);
    }
    Ok(stat)
}

fn same_inode(first: &rfs::Stat, second: &rfs::Stat) -> bool {
    first.st_dev == second.st_dev && first.st_ino == second.st_ino
}

fn ensure_current(dir: &File, file: &File, before: &rfs::Stat) -> Result<(), Error> {
    ensure_path(dir, FILE, file, before)
}

fn ensure_path(dir: &File, name: &str, file: &File, before: &rfs::Stat) -> Result<(), Error> {
    let now = rfs::fstat(file).map_err(io::Error::from)?;
    let entry = match rfs::statat(dir, name, rfs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Err(Error::Busy),
        Err(error) => return Err(io::Error::from(error).into()),
    };
    if same_snapshot(&now, before) && same_snapshot(&entry, before) {
        Ok(())
    } else {
        Err(Error::Busy)
    }
}

fn same_snapshot(a: &rfs::Stat, b: &rfs::Stat) -> bool {
    same_inode(a, b)
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_size == b.st_size
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
}

fn has_unchanged_block(bytes: &[u8], block: &[u8]) -> Result<bool, Error> {
    let mut offset = 0;
    let mut markers = bytes
        .split_inclusive(|byte| *byte == b'\n')
        .map(|line| {
            let start = offset;
            offset += line.len();
            (start, line)
        })
        .filter(|(_, line)| {
            line.windows(MARKER_PREFIX.len())
                .any(|word| word == MARKER_PREFIX)
        });

    let Some((start, opening)) = markers.next() else {
        return Ok(false);
    };
    let Some((_, digest)) = markers.next() else {
        return Err(Error::Ambiguous);
    };
    let Some((end, closing)) = markers.next() else {
        return Err(Error::Ambiguous);
    };
    if opening != START.as_bytes()
        || !digest.starts_with(DIGEST.as_bytes())
        || closing != END.as_bytes()
        || markers.next().is_some()
    {
        return Err(Error::Ambiguous);
    }
    if &bytes[start..end + closing.len()] != block {
        return Err(Error::Edited);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};

    #[test]
    fn external_append_between_staging_and_revalidation_is_preserved_on_retry() {
        let test_dir = tempfile::tempdir().unwrap();
        let dir = File::open(test_dir.path()).unwrap();
        let guide = test_dir.path().join(FILE);
        let original = b"# User text\n\n";
        let external = b"external editor append without a trailing newline";
        fs::write(&guide, original).unwrap();

        let mut attempts = 0;
        let receipt = install_with(&dir, &mut || {
            attempts += 1;
            if attempts == 1 {
                OpenOptions::new()
                    .append(true)
                    .open(&guide)?
                    .write_all(external)?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(receipt.status, Status::Installed);
        assert_eq!(attempts, 2);
        let block = format!(
            "{START}{DIGEST}{} -->\n{BODY}{END}",
            receipt.digest.as_str()
        );
        assert_eq!(
            fs::read(&guide).unwrap(),
            [original.as_slice(), external, b"\n\n", block.as_bytes()].concat()
        );
        assert_eq!(fs::read_dir(test_dir.path()).unwrap().count(), 1);
        assert_eq!(install(&dir).unwrap().status, Status::Unchanged);
    }
}
