#!/usr/bin/env python3
"""Safe evidence path handling for the M0.4 baseline runner.

The assessed worker can create arbitrary files, directories and symlinks in
its workspace. Evidence collection runs on the host after the worker exits and
must never follow a symlink, read through a path that escapes the workspace,
or write outside the evidence root.

All recursive copies go through `iter_workspace_files` and
`copy_workspace_tree`; all joins from untrusted names go through `safe_join`.
"""

import hashlib
import os
from pathlib import Path
import shutil
import stat


EXCLUDED_TOP = ".teapot"


class PathSafetyError(ValueError):
    """A relative name or resolved path would leave its declared root."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_label(value):
    """A trial label is one ordinary path component, never a path."""
    if not isinstance(value, str) or not value:
        raise PathSafetyError("label must be a non-empty string")
    path = Path(value)
    if path.is_absolute() or len(path.parts) != 1:
        raise PathSafetyError(f"label is not one path component: {value!r}")
    part = path.parts[0]
    if part in ("", ".", "..") or "\x00" in part:
        raise PathSafetyError(f"label is not a safe name: {value!r}")
    return part


def safe_join(root, relative):
    """Join an untrusted relative name under root, refusing escapes and links.

    The final component is checked with lstat by the caller when it matters;
    this function rejects absolute names, `.`/`..` components, NUL bytes, and
    any existing symlinked component that resolves outside root.
    """
    if not isinstance(relative, (str, os.PathLike)):
        raise PathSafetyError("relative name must be a path")
    text = os.fspath(relative)
    if not text or "\x00" in text:
        raise PathSafetyError("empty or NUL relative name")
    path = Path(text)
    if path.is_absolute():
        raise PathSafetyError(f"absolute name: {text!r}")
    if not path.parts:
        raise PathSafetyError(f"empty name: {text!r}")
    for part in path.parts:
        if part in ("", ".", ".."):
            raise PathSafetyError(f"unsafe path component in {text!r}")
    root = Path(root)
    try:
        resolved_root = root.resolve()
    except (OSError, RuntimeError) as error:
        raise PathSafetyError(f"cannot resolve root {root}: {error}") from error
    current = resolved_root
    for part in path.parts:
        current = current / part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            break
        except OSError as error:
            raise PathSafetyError(f"cannot inspect {current}: {error}") from error
        if stat.S_ISLNK(mode):
            raise PathSafetyError(f"symlink component is not allowed: {current}")
    candidate = resolved_root / path
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise PathSafetyError(f"path escapes {root}: {text!r}") from error
    return candidate


def _skipped(relative, reason):
    return {"path": relative, "reason": reason}


def iter_workspace_files(workspace):
    """Yield (relative path, absolute path) for regular files only.

    Directory symlinks are not descended. File symlinks, special files and the
    top-level Teapot store are returned in the skipped list. Relative paths are
    POSIX strings and always stay under the resolved workspace.
    """
    workspace = Path(workspace)
    if workspace.is_symlink():
        raise PathSafetyError(f"workspace is a symlink: {workspace}")
    root = workspace.resolve()
    if not root.is_dir():
        return [], [_skipped(".", "workspace-missing")]
    files = []
    skipped = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(dirpath)
        keep = []
        for name in sorted(dirnames):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if relative.split("/", 1)[0] == EXCLUDED_TOP:
                skipped.append(_skipped(relative, "excluded-instrument-store"))
                continue
            try:
                mode = os.lstat(path).st_mode
            except OSError as error:
                skipped.append(_skipped(relative, f"lstat-failed:{error.strerror}"))
                continue
            if stat.S_ISLNK(mode):
                skipped.append(_skipped(relative, "symlink-directory"))
            elif not stat.S_ISDIR(mode):
                skipped.append(_skipped(relative, "not-a-directory"))
            else:
                keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if relative.split("/", 1)[0] == EXCLUDED_TOP:
                skipped.append(_skipped(relative, "excluded-instrument-store"))
                continue
            try:
                info = os.lstat(path)
            except OSError as error:
                skipped.append(_skipped(relative, f"lstat-failed:{error.strerror}"))
                continue
            if stat.S_ISLNK(info.st_mode):
                skipped.append(_skipped(relative, "symlink-file"))
            elif not stat.S_ISREG(info.st_mode):
                skipped.append(_skipped(relative, "not-a-regular-file"))
            elif info.st_nlink != 1:
                skipped.append(_skipped(relative, "hardlink"))
            else:
                files.append((relative, path))
    files.sort(key=lambda item: item[0])
    skipped.sort(key=lambda item: item["path"])
    return files, skipped


def _open_regular_nofollow(path):
    """Open a regular, singly-linked file without following a symlink."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, os.O_RDONLY | nofollow)
    except OSError as error:
        raise PathSafetyError(f"cannot open regular file {path}: {error.strerror}") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PathSafetyError(f"not a regular file: {path}")
        if info.st_nlink != 1:
            raise PathSafetyError(f"hardlinked file refused: {path}")
    except BaseException:
        os.close(fd)
        raise
    return fd


def copy_regular_nofollow(source, destination):
    """Copy one regular, singly-linked file without following a symlink."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    source_fd = _open_regular_nofollow(source)
    try:
        try:
            destination_fd = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                0o600,
            )
        except FileExistsError as error:
            raise PathSafetyError(f"refusing to overwrite evidence file: {destination}") from error
        with os.fdopen(source_fd, "rb", closefd=False) as reader:
            with os.fdopen(destination_fd, "wb") as writer:
                shutil.copyfileobj(reader, writer, length=1 << 20)
                writer.flush()
                os.fsync(writer.fileno())
    finally:
        os.close(source_fd)


def read_regular_nofollow(path):
    """Read one regular, singly-linked file without following a symlink."""
    fd = _open_regular_nofollow(path)
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def sha256_regular_nofollow(path):
    """Hash one regular, singly-linked file without following a symlink."""
    fd = _open_regular_nofollow(path)
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def copy_workspace_tree(source, destination):
    """Recursively copy regular workspace files, preserving relative paths.

    Returns `{"files": {relative: {"bytes", "sha256"}}, "skipped": [...],
    "total_bytes": int}`. The destination directory is created if absent; an
    existing destination that is a symlink or contains files is refused.
    """
    source = Path(source)
    destination = Path(destination)
    if destination.is_symlink():
        raise PathSafetyError(f"destination is a symlink: {destination}")
    if destination.exists():
        if not destination.is_dir():
            raise PathSafetyError(f"destination is not a directory: {destination}")
        if any(destination.iterdir()):
            raise PathSafetyError(f"destination already has files: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    files, skipped = iter_workspace_files(source)
    copied = {}
    total = 0
    for relative, path in files:
        output = safe_join(destination, relative)
        output.parent.mkdir(parents=True, exist_ok=True)
        safe_join(destination, relative)
        copy_regular_nofollow(path, output)
        digest = sha256_file(output)
        size = output.stat().st_size
        copied[relative] = {"bytes": size, "sha256": digest}
        total += size
    return {"files": copied, "skipped": skipped, "total_bytes": total}
