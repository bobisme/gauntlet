"""Preflight, retain, and settle a stopped worker's evaluation capture."""

import argparse
from contextlib import contextmanager, nullcontext
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import secrets
import stat


SCHEMA_VERSION = 1
PREFLIGHT_SCHEMA = "scourge.trial-capture-preflight"
CAPTURE_SCHEMA = "scourge.trial-capture"
EVENTS = "raw/transcript.jsonl"
STDERR = "raw/worker.stderr"
RECEIPT = "capture.json"
RETAINED = "retained"

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
PIN_FLAGS = os.O_PATH | os.O_NOFOLLOW
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW


class CaptureError(ValueError):
    """A typed refusal that can be represented in a receipt."""

    def __init__(self, code, detail=None):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


def _issue(error, path=None):
    result = {"code": error.code if isinstance(error, CaptureError) else "io-error"}
    if isinstance(error, CaptureError) and error.detail:
        result["detail"] = error.detail
    if isinstance(error, OSError):
        result["errno"] = error.errno
    if path is not None:
        result["path"] = path
    return result


def _json_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _inventory_digest(rows):
    return hashlib.sha256(_json_bytes(rows)).hexdigest()


def _relative_parts(value):
    parts = value.split("/")
    if any(part in ("", ".", "..") or "\x00" in part or "\n" in part for part in parts):
        raise CaptureError("unsafe-relative-path", "expected an ordinary relative path")
    return parts


def _absolute_parts(value):
    if value == "/":
        return []
    if not value.startswith("/"):
        raise CaptureError("noncanonical-path", "expected an absolute canonical path")
    try:
        return _relative_parts(value[1:])
    except CaptureError as error:
        raise CaptureError("noncanonical-path", "expected an absolute canonical path") from error


@contextmanager
def _directory(parts, base=None, *, mount_id=None):
    """Anchor traversal in directory descriptors, with no symlink resolution."""
    fd = os.open("/", DIR_FLAGS) if base is None else os.dup(base)
    chain = []
    try:
        for part in parts:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            if mount_id is not None and _mount_id(fd) != mount_id:
                raise CaptureError("mount-crossing")
            chain.append(_identity(os.fstat(fd)))
        yield fd, chain
    finally:
        os.close(fd)


def _identity(info):
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner_uid": info.st_uid,
        "mode": stat.S_IMODE(info.st_mode),
    }


def _snapshot(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
        info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _private(fd):
    info = _identity(os.fstat(fd))
    if info["owner_uid"] != os.geteuid() or info["mode"] != 0o700:
        raise CaptureError("not-private", "expected a directory owned by the effective user with mode 0700")
    return info


def _overlaps(left, right):
    return left == right or left in right.parents or right in left.parents


def _guard_external(path, checkout, excluded):
    path = Path(path)
    # Reject a checkout or any ancestor. A checkout passed by a MAW worker can
    # be nested within the primary checkout and must protect that root as well.
    checkout = Path(checkout).resolve(strict=True)
    roots = [checkout]
    for parent in checkout.parents:
        git = parent / ".git"
        if git.is_file() or (git / "HEAD").is_file():
            roots.append(parent)
    home_roots = {Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve()}
    if home := os.environ.get("HOME"):
        home_roots.add(Path(home).resolve())
    if any(path == home or path in home.parents for home in home_roots):
        raise CaptureError("sensitive-run-root", "run root contains a user home")
    for home in home_roots:
        roots.extend(home / name for name in (
            ".ssh", ".aws", ".gnupg", ".config", ".cache", ".local",
            ".codex", ".cargo", ".git", ".kube",
        ))
    roots.extend(Path(name) for name in ("/etc", "/proc", "/sys", "/dev", "/run"))
    roots.extend(Path(value) for value in excluded)
    roots.extend(
        Path(os.environ[key]) for key in (
            "CODEX_HOME", "CARGO_HOME", "RITE_DATA_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
            "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "TMUX_TMPDIR", "VESSEL_SOCKET",
        ) if os.environ.get(key)
    )
    if any(_overlaps(path, root.resolve()) for root in roots):
        raise CaptureError("sensitive-run-root", "run root overlaps a checkout or protected location")


def _atomic_receipt(directory_fd, value):
    data = _json_bytes(value) + b"\n"
    temporary = f".capture-{secrets.token_hex(12)}.tmp"
    fd = os.open(temporary, CREATE_FLAGS, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, "wb") as writer:
            writer.write(data)
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temporary, RECEIPT, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _probe(directory_fd, evidence):
    name = f".capture-preflight-{secrets.token_hex(12)}"
    payload = b"scourge capture preflight\n"
    fd = os.open(name, CREATE_FLAGS, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, "wb") as writer:
            evidence["bytes_written"] = writer.write(payload)
            writer.flush()
            evidence["flushed"] = True
            os.fsync(writer.fileno())
            evidence["file_synced"] = True
            if os.fstat(writer.fileno()).st_size != len(payload):
                raise CaptureError("short-probe-write")
    finally:
        os.unlink(name, dir_fd=directory_fd)
        evidence["unlinked"] = True
        os.fsync(directory_fd)
        evidence["directory_synced"] = True


def preflight(run_root, checkout, min_bytes, min_inodes, *, exclude_roots=()):
    """Exercise the run-root filesystem and report measured capacity."""
    run_root, checkout = os.fspath(run_root), os.fspath(checkout)
    evidence = {
        "schema": PREFLIGHT_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "run_root": run_root,
        "checkout": checkout,
        "exclude_roots": [os.fspath(root) for root in exclude_roots],
        "root_identity": None,
        "write_probe": {
            "bytes_written": 0, "flushed": False, "file_synced": False,
            "unlinked": False, "directory_synced": False,
        },
        "capacity": {
            "minimum_bytes": min_bytes, "minimum_inodes": min_inodes,
            "available_bytes": None, "available_inodes": None,
        },
        "passed": False,
        "reasons": [],
    }
    try:
        parts = _absolute_parts(run_root)
        _absolute_parts(checkout)
        for root in evidence["exclude_roots"]:
            _absolute_parts(root)
        if any(type(value) is not int or value < 1 for value in (min_bytes, min_inodes)):
            raise CaptureError("invalid-capacity-minimum", "byte and inode minima must be positive integers")
        _guard_external(run_root, checkout, evidence["exclude_roots"])
        with _directory(parts) as (fd, chain):
            root_info = evidence["root_identity"] = _private(fd)
            _probe(fd, evidence["write_probe"])
            volume = os.fstatvfs(fd)
            capacity = evidence["capacity"]
            capacity["available_bytes"] = volume.f_bavail * volume.f_frsize
            capacity["available_inodes"] = volume.f_favail
            if capacity["available_bytes"] < min_bytes:
                evidence["reasons"].append({"code": "insufficient-bytes"})
            if capacity["available_inodes"] < min_inodes:
                evidence["reasons"].append({"code": "insufficient-inodes"})
            with _directory(parts) as (current, current_chain):
                if _private(current) != root_info or current_chain != chain:
                    raise CaptureError("path-changed", "run root changed during preflight")
    except (CaptureError, OSError, RuntimeError) as error:
        evidence["reasons"].append(_issue(error))
    evidence["passed"] = not evidence["reasons"]
    return evidence


def _trial_part(trial_id):
    parts = _relative_parts(trial_id)
    if len(parts) != 1:
        raise CaptureError("invalid-trial-id", "expected one path component")
    return parts[0]


def pending(run_root, checkout, min_bytes, min_inodes, trial_id, *,
            exclude_roots=(), terminal_event="turn.completed"):
    """Publish a pending receipt in a new private trial directory."""
    trial_id = _trial_part(trial_id)
    if not isinstance(terminal_event, str) or not terminal_event.strip():
        raise CaptureError("invalid-terminal-event")
    evidence = preflight(run_root, checkout, min_bytes, min_inodes, exclude_roots=exclude_roots)
    if not evidence["passed"]:
        return {**evidence, "status": "refused", "settled": False, "valid": False, "score": None}
    run_root = evidence["run_root"]
    with _directory(_absolute_parts(run_root)) as (root_fd, _):
        if _private(root_fd) != evidence["root_identity"]:
            raise CaptureError("path-changed", "run root changed after preflight")
        os.mkdir(trial_id, 0o700, dir_fd=root_fd)
        with _directory([trial_id], root_fd) as (trial_fd, _):
            receipt = {
                "schema": CAPTURE_SCHEMA,
                "schema_version": SCHEMA_VERSION,
                "trial_id": trial_id,
                "trial_identity": _private(trial_fd),
                "status": "pending",
                "settled": False,
                "valid": False,
                "score": None,
                "terminal_event_type": terminal_event,
                "preflight": evidence,
                "reasons": [],
            }
            _atomic_receipt(trial_fd, receipt)
        os.fsync(root_fd)
        with _directory(_absolute_parts(run_root) + [trial_id]) as (current, _):
            if _private(current) != receipt["trial_identity"]:
                raise CaptureError("path-changed", "trial directory changed during pending publication")
    return receipt


def _entry_kind(info):
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISLNK(info.st_mode):
        raise CaptureError("symlink")
    if not stat.S_ISREG(info.st_mode):
        raise CaptureError("special-file")
    if info.st_nlink != 1:
        raise CaptureError("hardlink")
    return "file"


def _mount_id(fd):
    # st_dev alone cannot detect a bind mount onto the same filesystem.
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as handle:
        for line in handle:
            if line.startswith("mnt_id:"):
                return int(line.split()[1])
    raise CaptureError("mount-identity-unavailable")


def _assert_same(before, current):
    if _snapshot(before) != _snapshot(current):
        raise CaptureError("path-changed", "entry changed during capture")


@contextmanager
def _regular(parent_fd, name, before, mount_id):
    # O_PATH pins an inode without opening a FIFO/device swapped in after lstat.
    # The kernel's /proc/self/fd link reopens that pinned inode for data I/O.
    pin = os.open(name, PIN_FLAGS, dir_fd=parent_fd)
    try:
        _assert_same(before, os.fstat(pin))
        if _mount_id(pin) != mount_id:
            raise CaptureError("mount-crossing")
        fd = os.open(f"/proc/self/fd/{pin}", os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as reader:
            _assert_same(before, os.fstat(fd))
            yield reader
            _assert_same(before, os.fstat(fd))
            _assert_same(before, os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
    finally:
        os.close(pin)


@contextmanager
def _destination(directory_fd, name):
    if directory_fd is None:
        yield None
        return
    fd = os.open(name, CREATE_FLAGS, 0o600, dir_fd=directory_fd)
    with os.fdopen(fd, "wb") as writer:
        yield writer
        writer.flush()
        os.fsync(writer.fileno())


def _file_row(parent_fd, name, before, path, destination_fd, destination_name, mount_id):
    digest = hashlib.sha256()
    count = 0
    with _regular(parent_fd, name, before, mount_id) as reader:
        with _destination(destination_fd, destination_name) as writer:
            while chunk := reader.read(1 << 20):
                if writer is not None:
                    writer.write(chunk)
                digest.update(chunk)
                count += len(chunk)
    if count != before.st_size:
        raise CaptureError("path-changed", "source byte count changed during capture")
    return {"path": path, "type": "file", "bytes": count, "sha256": digest.hexdigest()}


def _dir_row(path):
    return {"path": path, "type": "directory", "bytes": 0, "sha256": None}


class Inventory:
    """A traversal's inventory and private race-check metadata."""

    def __init__(self, root_fd, *, hash_files=True):
        self.mount_id = _mount_id(root_fd)
        self.hash_files = hash_files
        self.rows = []
        self.snapshots = {}
        self.issues = []

    def capture(self, parent_fd, name, path, *, expected=None,
                destination_fd=None, destination_name=None):
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            kind = _entry_kind(before)
            if expected is not None and expected != kind:
                raise CaptureError("wrong-entry-type", f"{expected} required")
            if kind == "directory":
                self._directory(parent_fd, name, before, path, destination_fd, destination_name)
            elif self.hash_files:
                self.rows.append(_file_row(
                    parent_fd, name, before, path, destination_fd, destination_name, self.mount_id
                ))
            self.snapshots[path] = _snapshot(before)
        except (CaptureError, OSError, RecursionError) as error:
            self.issues.append(_issue(error, path))

    def _directory(self, parent_fd, name, before, path, destination_fd, destination_name):
        with _directory([name], parent_fd, mount_id=self.mount_id) as (opened, _):
            _assert_same(before, os.fstat(opened))
            self.rows.append(_dir_row(path))
            if destination_fd is None:
                self.contents(opened, path)
            else:
                os.mkdir(destination_name, 0o700, dir_fd=destination_fd)
                with _directory([destination_name], destination_fd,
                                mount_id=_mount_id(destination_fd)) as (output, _):
                    _private(output)
                    self.contents(opened, path, output)
                    os.fsync(output)
            _assert_same(before, os.fstat(opened))
            _assert_same(before, os.stat(name, dir_fd=parent_fd, follow_symlinks=False))

    def contents(self, directory_fd, prefix="", destination_fd=None):
        for name in sorted(os.listdir(directory_fd)):
            path = f"{prefix}/{name}" if prefix else name
            self.capture(directory_fd, name, path, destination_fd=destination_fd, destination_name=name)

    def selected(self, root_fd, relative, alias, expected, destination_fd=None):
        try:
            parts = _relative_parts(relative)
            with _directory(parts[:-1], root_fd, mount_id=self.mount_id) as (parent_fd, chain):
                self.snapshots[f"parents:{alias}"] = chain
                self.capture(
                    parent_fd, parts[-1], alias, expected=expected,
                    destination_fd=destination_fd, destination_name=alias.rsplit("/", 1)[-1],
                )
        except (CaptureError, OSError) as error:
            self.issues.append(_issue(error, alias))

    def sorted_rows(self):
        return sorted(self.rows, key=lambda row: row["path"])


def _selected_inputs(inventory, source_fd, inputs, retained_fd=None):
    inventory.rows.append(_dir_row("raw"))
    destination = nullcontext((None, []))
    try:
        if retained_fd is not None:
            os.mkdir("raw", 0o700, dir_fd=retained_fd)
            destination = _directory(["raw"], retained_fd, mount_id=_mount_id(retained_fd))
        with destination as (raw_fd, _):
            if raw_fd is not None:
                _private(raw_fd)
            inventory.selected(source_fd, inputs["events"], EVENTS, "file", raw_fd)
            inventory.selected(source_fd, inputs["stderr"], STDERR, "file", raw_fd)
            if raw_fd is not None:
                os.fsync(raw_fd)
    except (CaptureError, OSError) as error:
        inventory.issues.append(_issue(error, "raw"))
    inventory.selected(source_fd, inputs["artifacts"], "artifacts", "directory", retained_fd)


def _unique_object(pairs):
    object_value = {}
    for key, value in pairs:
        if key in object_value:
            raise ValueError("duplicate JSON key")
        object_value[key] = value
    return object_value


def _finite_number(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite JSON number")
    return number


def _event_prefix(reader, terminal_type):
    result = {
        "valid_prefix_events": 0, "valid_prefix_bytes": 0, "valid_prefix_sha256": None,
        "terminal_line": None, "last_event_type": None, "usage": [],
        "model_input_tokens": None, "model_output_tokens": None,
        "provider_reported_model": None, "issues": [],
    }
    digest = hashlib.sha256()
    for number, line in enumerate(reader, start=1):
        if line.strip(b" \t\r\n"):
            try:
                if not line.endswith(b"\n"):
                    raise CaptureError("torn-event")
                try:
                    event = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object,
                                       parse_constant=_finite_number, parse_float=_finite_number)
                except (ValueError, RecursionError) as error:
                    raise CaptureError("malformed-event") from error
                if (not isinstance(event, dict) or not isinstance(event.get("type"), str)
                        or not event["type"].strip()):
                    raise CaptureError("malformed-event", "expected an event object with a type")
                if "usage" in event and not isinstance(event["usage"], dict):
                    raise CaptureError("malformed-event", "expected a usage object")
                if result["terminal_line"] is not None:
                    raise CaptureError("post-terminal-event")
            except CaptureError as error:
                result["issues"].append({**_issue(error), "line": number})
                break
            kind = event["type"]
            result["valid_prefix_events"] += 1
            result["last_event_type"] = kind
            if kind == terminal_type:
                result["terminal_line"] = number
            if isinstance(event.get("model"), str):
                result["provider_reported_model"] = event["model"]
            if "usage" in event:
                usage = event["usage"]
                result["usage"].append(usage)
                for field in ("input_tokens", "output_tokens"):
                    value = usage.get(field)
                    if type(value) is int and value >= 0:
                        result[f"model_{field}"] = value
        digest.update(line)
        result["valid_prefix_bytes"] += len(line)
    result["valid_prefix_sha256"] = digest.hexdigest()
    if result["terminal_line"] is None:
        result["issues"].append({"code": "missing-terminal-event"})
    return result


def _retained_events(retained_fd, retained, terminal_type):
    with _directory(["raw"], retained_fd) as (raw_fd, _):
        name = EVENTS.rsplit("/", 1)[-1]
        before = os.stat(name, dir_fd=raw_fd, follow_symlinks=False)
        if _entry_kind(before) != "file" or _snapshot(before) != retained.snapshots.get(EVENTS):
            raise CaptureError("path-changed", "retained event file changed after inventory")
        with _regular(raw_fd, name, before, retained.mount_id) as reader:
            return _event_prefix(reader, terminal_type)


def _collect(trial_fd, trial_root, trial_chain, inputs, terminal_type, preflight_evidence):
    source_rows, retained_rows, issues = [], [], []
    events = None
    try:
        source_root = inputs["source_root"]
        source_parts = _absolute_parts(source_root)
        if _overlaps(Path(source_root), trial_root):
            raise CaptureError("overlapping-source", "source and trial directories must be disjoint")
        _guard_external(source_root, preflight_evidence["checkout"], preflight_evidence["exclude_roots"])
        with _directory(source_parts) as (source_fd, source_chain):
            # Compare inode identities as well as paths, so aliases of an
            # ancestor cannot cause the copier to retain its own destination.
            def inode(entry):
                return entry["device"], entry["inode"]

            if (inode(source_chain[-1]) in map(inode, trial_chain)
                    or inode(trial_chain[-1]) in map(inode, source_chain)):
                raise CaptureError("overlapping-source", "source and trial directories must be disjoint")
            source_before = os.fstat(source_fd)
            os.mkdir(RETAINED, 0o700, dir_fd=trial_fd)
            with _directory([RETAINED], trial_fd, mount_id=_mount_id(trial_fd)) as (retained_fd, _):
                _private(retained_fd)
                source, retained = Inventory(source_fd), Inventory(retained_fd)
                _selected_inputs(source, source_fd, inputs, retained_fd)
                source_rows = source.sorted_rows()
                issues.extend({"phase": "source", **issue} for issue in source.issues)
                retained_before = os.fstat(retained_fd)
                retained.contents(retained_fd)
                retained_rows = retained.sorted_rows()
                issues.extend({"phase": "retained", **issue} for issue in retained.issues)
                if EVENTS in retained.snapshots:
                    try:
                        events = _retained_events(retained_fd, retained, terminal_type)
                    except (CaptureError, OSError) as error:
                        issues.append({"phase": "retained", **_issue(error, EVENTS)})
                source_after = Inventory(source_fd, hash_files=False)
                _selected_inputs(source_after, source_fd, inputs)
                if (source.snapshots != source_after.snapshots
                        or (source_after.issues and not source.issues)):
                    raise CaptureError("path-changed", "source inventory changed during capture")
                retained_after = Inventory(retained_fd, hash_files=False)
                retained_after.contents(retained_fd)
                if (retained.snapshots != retained_after.snapshots
                        or (retained_after.issues and not retained.issues)):
                    raise CaptureError("path-changed", "retained inventory changed during verification")
                with _directory(source_parts) as (current_fd, current_chain):
                    _assert_same(source_before, os.fstat(current_fd))
                    if source_chain != current_chain:
                        raise CaptureError("path-changed", "source directory changed during capture")
                with _directory([RETAINED], trial_fd) as (current_fd, _):
                    _assert_same(retained_before, os.fstat(current_fd))
                os.fsync(retained_fd)
            os.fsync(trial_fd)
    except (CaptureError, OSError, RuntimeError) as error:
        issues.append({"phase": "collection", **_issue(error)})

    complete = not issues and [row["path"] for row in source_rows] == [
        row["path"] for row in retained_rows
    ]
    return {
        "complete": complete,
        "verified": complete and source_rows == retained_rows,
        "source": source_rows,
        "retained": retained_rows,
        "source_sha256": _inventory_digest(source_rows),
        "retained_sha256": _inventory_digest(retained_rows),
        "issues": issues,
    }, events


def _load_pending(trial_fd, trial_id, trial_identity, root_identity, run_root):
    info = os.stat(RECEIPT, dir_fd=trial_fd, follow_symlinks=False)
    if (_entry_kind(info) != "file" or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid()):
        raise CaptureError("unsafe-receipt")
    with _regular(trial_fd, RECEIPT, info, _mount_id(trial_fd)) as reader:
        try:
            receipt = json.load(reader, object_pairs_hook=_unique_object,
                                parse_constant=_finite_number, parse_float=_finite_number)
        except (ValueError, RecursionError) as error:
            raise CaptureError("invalid-receipt") from error
    if (not isinstance(receipt, dict) or receipt.get("schema") != CAPTURE_SCHEMA
            or receipt.get("schema_version") != SCHEMA_VERSION
            or receipt.get("trial_id") != trial_id or receipt.get("trial_identity") != trial_identity):
        raise CaptureError("invalid-receipt")
    if receipt.get("status") != "pending":
        raise CaptureError("already-finalized")
    evidence = receipt.get("preflight")
    if (not isinstance(evidence, dict) or evidence.get("passed") is not True
            or evidence.get("schema") != PREFLIGHT_SCHEMA
            or evidence.get("schema_version") != SCHEMA_VERSION
            or evidence.get("root_identity") != root_identity or evidence.get("run_root") != run_root
            or not isinstance(evidence.get("checkout"), str)
            or not isinstance(evidence.get("exclude_roots"), list)
            or not isinstance(receipt.get("terminal_event_type"), str)
            or not receipt["terminal_event_type"].strip()):
        raise CaptureError("invalid-receipt")
    return receipt


def settle(run_root, trial_id, source_root, *, events, stderr, artifacts,
           exit_code=None, worker_stopped=False, interrupted=False, safety_ok=False, boundary_ok=False):
    """Retain evidence from a stopped worker and finalize its pending receipt."""
    run_root = os.fspath(run_root)
    root_parts = _absolute_parts(run_root)
    trial_id = _trial_part(trial_id)
    trial_root = Path(run_root) / trial_id
    inputs = {"source_root": os.fspath(source_root), "events": events,
              "stderr": stderr, "artifacts": artifacts}
    with _directory(root_parts) as (root_fd, root_chain):
        root_identity = _private(root_fd)
        with _directory([trial_id], root_fd) as (trial_fd, _):
            trial_identity = _private(trial_fd)
            try:
                fcntl.flock(trial_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise CaptureError("settlement-in-progress") from error
            receipt = _load_pending(trial_fd, trial_id, trial_identity, root_identity, run_root)
            reasons = []
            for passed, code in (
                (worker_stopped is True, "worker-not-stopped"),
                (interrupted is False, "interrupted"),
                (type(exit_code) is int and exit_code == 0,
                    "missing-command-receipt" if exit_code is None else "nonzero-command"),
                (safety_ok is True, "safety-check-failed"),
                (boundary_ok is True, "boundary-check-failed"),
            ):
                if not passed:
                    reasons.append({"code": code})

            inventory = event_summary = None
            if worker_stopped is True:
                inventory, event_summary = _collect(
                    trial_fd, trial_root, root_chain + [trial_identity], inputs,
                    receipt["terminal_event_type"], receipt["preflight"],
                )
                if not inventory["complete"]:
                    reasons.append({"code": "inventory-incomplete"})
                elif not inventory["verified"]:
                    reasons.append({"code": "inventory-mismatch"})
                if event_summary is None:
                    reasons.append({"code": "event-capture-unavailable"})
                else:
                    reasons.extend(event_summary["issues"])

            try:
                with _directory(root_parts + [trial_id]) as (current_fd, current_chain):
                    if (current_chain[:-1] != root_chain
                            or _private(current_fd) != trial_identity):
                        raise CaptureError("path-changed", "trial directory changed during settlement")
            except (CaptureError, OSError) as error:
                reasons.append(_issue(error))

            receipt.update({
                "status": "unsettled" if reasons else "settled",
                "settled": not reasons, "valid": not reasons, "score": None,
                "process": {
                    "exit_code": exit_code, "worker_stopped": worker_stopped, "interrupted": interrupted,
                },
                "checks": {"safety_ok": safety_ok, "boundary_ok": boundary_ok},
                "inputs": inputs, "inventory": inventory, "events": event_summary, "reasons": reasons,
            })
            _atomic_receipt(trial_fd, receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("preflight", help="measure a private external run root")
    begin = commands.add_parser("pending", help="preflight and publish a pending trial receipt")
    end = commands.add_parser("settle", help="retain a stopped worker's evidence and finalize its receipt")
    for command in (prepare, begin, end):
        command.add_argument("--run-root", required=True)
    for command in (prepare, begin):
        command.add_argument("--checkout", required=True)
        command.add_argument("--min-bytes", type=int, required=True)
        command.add_argument("--min-inodes", type=int, required=True)
        command.add_argument("--exclude-root", action="append", default=[])
    for command in (begin, end):
        command.add_argument("--trial-id", required=True)
    begin.add_argument("--terminal-event", default="turn.completed")
    end.add_argument("--source-root", required=True)
    end.add_argument("--events", required=True)
    end.add_argument("--stderr", required=True)
    end.add_argument("--artifacts", required=True)
    end.add_argument("--exit-code", type=int)
    for check in ("interrupted", "worker-stopped", "safety-ok", "boundary-ok"):
        end.add_argument(f"--{check}", action="store_true")
    args = parser.parse_args()

    try:
        if args.command == "settle":
            result = settle(
                args.run_root, args.trial_id, args.source_root, events=args.events, stderr=args.stderr,
                artifacts=args.artifacts, exit_code=args.exit_code, worker_stopped=args.worker_stopped,
                interrupted=args.interrupted, safety_ok=args.safety_ok, boundary_ok=args.boundary_ok,
            )
            accepted = result["settled"]
        else:
            common = (args.run_root, args.checkout, args.min_bytes, args.min_inodes)
            if args.command == "pending":
                result = pending(*common, args.trial_id, exclude_roots=args.exclude_root,
                                 terminal_event=args.terminal_event)
                accepted = result.get("status") == "pending"
            else:
                result = preflight(*common, exclude_roots=args.exclude_root)
                accepted = result["passed"]
    except (CaptureError, OSError, ValueError) as error:
        result = {
            "schema": CAPTURE_SCHEMA, "schema_version": SCHEMA_VERSION,
            "status": "refused", "settled": False, "valid": False, "score": None,
            "reasons": [_issue(error)],
        }
        accepted = False
    print(_json_bytes(result).decode("ascii"))
    return 0 if accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
