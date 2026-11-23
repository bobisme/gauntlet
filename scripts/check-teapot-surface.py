#!/usr/bin/env python3
"""Validate the Teapot surface map against Scourge's immutable source pin."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "packs" / "teapot-surface.json"
VALID_CLASSES = {"web-authz/private-object-read", "web-authz/forbidden-state-change"}

def fail(message):
    raise SystemExit(f"teapot-surface: {message}")

def run(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.PIPE).strip()
    except subprocess.CalledProcessError as exc:
        fail(f"command failed: {' '.join(args)}: {exc.stderr.strip()}")

def source_file(source, commit, path):
    return subprocess.check_output(["git", "-C", str(source), "show", f"{commit}:{path}"])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--teapot-source", type=Path, default=Path("/home/bob/src/teapot"),
                        help="local Teapot Git checkout containing the pinned object (no network used)")
    args = parser.parse_args()
    data = json.loads(DATA.read_text())
    inventory = json.loads((ROOT / "docs/inventory.json").read_text())
    manifest = json.loads((ROOT / "fixtures/contracts/manifest.json").read_text())
    inv = next(tool for tool in inventory["tools"] if tool["tool"] == "teapot")
    commit = data["source"]["commit"]
    if commit != manifest["source_commit"] or commit != inv["checkout"]["head"]:
        fail("pack pin differs from contract manifest or inventory checkout HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("source commit must be a full immutable object ID")
    tree = run("git", "-C", str(args.teapot_source), "rev-parse", f"{commit}^{{tree}}")
    if tree != data["source"]["tree"]:
        fail(f"source tree drift: expected {data['source']['tree']}, found {tree}")
    blobs = []
    payloads = {}
    for record in data["source"]["files"]:
        path = record["path"]
        payload = source_file(args.teapot_source, commit, path)
        digest = hashlib.sha256(payload).hexdigest()
        if digest != record["sha256"]:
            fail(f"source digest drift for {path}: expected {record['sha256']}, found {digest}")
        payloads[path] = payload.decode("utf-8")
        blobs.append(path.encode() + b"\0" + bytes.fromhex(digest) + b"\n")
    source_digest = hashlib.sha256(b"".join(blobs)).hexdigest()
    if source_digest != data["source"]["sha256"]:
        fail(f"aggregate source digest drift: expected {data['source']['sha256']}, found {source_digest}")

    catalog_path = "crates/teapot-lua/src/loader/bundled.rs"
    if catalog_path not in payloads:
        fail("source digest set omits the bundled script catalog")
    catalog = payloads[catalog_path].split("pub const ALL", 1)[1].split("];", 1)[0]
    catalog_scripts = {
        "crates/teapot-lua/bundled/" + name
        for name in re.findall(
            r'include_str!\("../../bundled/([^\"]+\.lua)"\)', catalog
        )
    }
    mapped_scripts = {
        path for path in payloads
        if path.startswith("crates/teapot-lua/bundled/")
    }
    if catalog_scripts != mapped_scripts:
        fail(f"bundled script coverage drift: unpinned={sorted(catalog_scripts-mapped_scripts)}; not_in_catalog={sorted(mapped_scripts-catalog_scripts)}")

    found = []
    for path, text in payloads.items():
        if path.startswith("crates/teapot-lua/bundled/") and path != "crates/teapot-lua/bundled/lead-rules.lua":
            found.extend(item for item in re.findall(r'\bid\s*=\s*"([a-z][a-z0-9.-]+)"', text) if item != "disclosure.secret-")
            if path.endswith("passive-secrets.lua"):
                kinds = re.findall(r'token_check\s*\{\s*kind\s*=\s*"([a-z][a-z0-9-]+)"', text)
                found.extend("disclosure.secret-" + kind for kind in kinds)
        elif path.endswith("crates/teapot-engine/src/checks/authz.rs"):
            match = re.search(r'pub const ID:\s*&str\s*=\s*"([^"]+)"', text)
            if not match:
                fail("could not extract built-in check ID from authz.rs")
            found.append(match.group(1))
    duplicates = sorted({item for item in found if found.count(item) > 1})
    if duplicates:
        fail("duplicate source check IDs: " + ", ".join(duplicates))
    rows = data.get("checks")
    if not isinstance(rows, list):
        fail("checks must be a list")
    declared_classes = set(data.get("classes", []))
    if declared_classes != VALID_CLASSES:
        fail(f"unknown or missing declared classes: {sorted(declared_classes ^ VALID_CLASSES)}")
    if set(data.get("class_semantics", {})) != VALID_CLASSES:
        fail("class_semantics must define exactly the supported classes")
    ids = [row.get("id") for row in rows]
    duplicate_rows = sorted({item for item in ids if ids.count(item) > 1})
    if duplicate_rows:
        fail("duplicate pack check IDs: " + ", ".join(map(str, duplicate_rows)))
    if set(ids) != set(found):
        fail(f"check inventory drift: missing={sorted(set(found)-set(ids))}; unknown={sorted(set(ids)-set(found))}")
    for row in rows:
        check_id, cls = row["id"], row.get("class")
        if cls is not None and cls not in VALID_CLASSES:
            fail(f"unknown class {cls!r} for {check_id}")
        if cls is None and not row.get("unmapped_reason", "").strip():
            fail(f"unmapped check {check_id} has no reason")
        if cls is not None and not row.get("mapping_basis", "").strip():
            fail(f"mapped check {check_id} has no source-semantic basis")
    print(f"OK: {len(rows)} unique check IDs match Teapot {commit}; source tree and {len(blobs)} file digests verified; classes valid.")

if __name__ == "__main__":
    main()
