#!/usr/bin/env python3
"""Record the existing acceptance checks on the harness-owned local package."""

import hashlib
import json
from functools import partial
from pathlib import Path
import sys
import tomllib

from check_catalog import check_catalog
from http_fixture import login, request_http


REQUEST_LIMIT = 300


def observe(port, package):
    if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("expected the harness fixture's loopback port")
    authority = f"127.0.0.1:{port}"
    catalog = (package / "ground-truth.json").read_bytes()
    truth = json.loads(catalog)
    if truth["schema_version"] != 1 or truth["fixture"] != "scourge-fixture":
        raise ValueError("unexpected packaged fixture catalog")
    fixture_dir = Path(__file__).resolve().parents[1]
    with (fixture_dir / "example" / "engagement.toml").open("rb") as source:
        engagement = tomllib.load(source)
    secret = (package / "admin-secret").read_text(encoding="ascii").strip()
    requests = 0

    def request(line, **options):
        nonlocal requests
        if requests >= REQUEST_LIMIT:
            raise RuntimeError("referee fixture request budget exhausted")
        requests += 1
        return request_http(authority, line, **options)

    observations = check_catalog(truth, engagement, request, partial(login, request),
                                 secret, default_only=True)
    with (package / "scourge-fixture").open("rb") as binary:
        binary_digest = hashlib.file_digest(binary, "sha256").hexdigest()
    return {
        "schema_version": 1,
        "fixture": "scourge-fixture",
        "fixture_binary_sha256": binary_digest,
        "catalog_sha256": hashlib.sha256(catalog).hexdigest(),
        "referee_target_requests": requests,
        "referee_request_limit": REQUEST_LIMIT,
        "reset_after_checks": True,
        "observations": observations,
    }


if __name__ == "__main__":
    print(json.dumps(observe(sys.argv[1], Path(sys.argv[2])), indent=2, sort_keys=True))
