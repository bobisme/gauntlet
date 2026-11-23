#!/usr/bin/env python3
"""Replay the fixture finding rubric from the catalog, live receipt, and transcript."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


RUBRIC = "fixture-findings-v1"
NAME = re.compile(r"[a-z][a-z0-9_]{0,79}")
GROUPS = {"flaws": "true_violation", "decoys": "keyed_decoy", "controls": "keyed_control"}


def claim_is_well_formed(claim):
    return (
        isinstance(claim, dict)
        and claim.keys() == {"case", "property", "qualification", "observation"}
        and all(isinstance(claim[field], str) and NAME.fullmatch(claim[field])
                for field in ("case", "property"))
        and (claim["qualification"] is None
             or isinstance(claim["qualification"], str) and NAME.fullmatch(claim["qualification"]))
        and isinstance(claim["observation"], str)
        and 0 < len(claim["observation"].strip()) <= 1000
    )


def grade_claim(claim, key, observations):
    if not claim_is_well_formed(claim):
        return "malformed", "Expected a case, property, observation, and explicit qualification."
    name = claim["case"]
    for group, classification in GROUPS.items():
        entry = key[group].get(name)
        if entry is None:
            continue
        state = observations[group].get(name)
        if (not state or state.get("expected") != entry["expected"]
                or state.get("property") != entry.get("property")
                or any(entry.get(field) != value for field, value in state.items())):
            return "unsupported", "The live referee receipt does not corroborate the catalog entry."
        if "property" in entry and claim["property"] != entry["property"]:
            return "unsupported", "The claim names a different property than the catalog entry."
        if group == "flaws":
            if claim["qualification"] != state["expected"].get("qualification"):
                return "unsupported", "The claim omits or changes the observed qualification."
            return classification, "The catalog and live fixture observation agree."
        return classification, entry.get("behavior", state["expected"].get("reason", name))
    return "needs_adjudication", "The case is absent from the key. Review the submitted observation independently."


def grade(findings, key, receipt):
    if (key["schema_version"], key["fixture"]) != (1, "scourge-fixture"):
        raise ValueError("unexpected ground-truth format")
    if (receipt["schema_version"], receipt["fixture"]) != (1, key["fixture"]) or not receipt["reset_after_checks"]:
        raise ValueError("expected a completed live fixture receipt and reset")
    if not isinstance(findings, list):
        raise ValueError("worker result must contain a findings list")

    rows = []
    seen = set()
    for claim in findings:
        classification, reason = grade_claim(claim, key, receipt["observations"])
        if claim_is_well_formed(claim):
            # Distinct asserted cases and scopes count once even if the prose differs.
            fingerprint = (claim["case"], claim["property"], claim["qualification"])
            if fingerprint in seen:
                classification, reason = "duplicate", "This case and scope were already submitted."
            seen.add(fingerprint)
        rows.append({"claim": claim, "classification": classification, "reason": reason})

    counts = Counter(row["classification"] for row in rows)
    correct = counts["true_violation"]
    total = len(key["flaws"])
    pending = counts["needs_adjudication"]
    unsupported = sum(counts[c] for c in ("keyed_decoy", "keyed_control", "malformed", "unsupported"))
    if pending:
        verdict = "needs_adjudication"
    elif unsupported:
        verdict = "failed"
    elif not findings:
        verdict = "abstained"
    elif correct == total:
        verdict = "passed"
    else:
        verdict = "incomplete"
    assessed = correct + unsupported
    return {
        "rubric": RUBRIC,
        "verdict": verdict,
        "completed": True,
        "submitted": len(findings),
        "points": correct,
        "total": total,
        "recall": correct / total if total else None,
        "precision": correct / assessed if assessed and not pending else None,
        "counts": {c: counts[c] for c in (*GROUPS.values(), "needs_adjudication",
                                        "unsupported", "malformed", "duplicate")},
        "findings": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("transcript", type=Path)
    args = parser.parse_args()
    catalog = args.catalog.read_bytes()
    receipt = args.receipt.read_bytes()
    transcript = args.transcript.read_bytes()
    events = [json.loads(line) for line in transcript.splitlines()]
    results = [event for event in events if event["type"] == "result"]
    if len(results) != 1 or results[0]["subtype"] != "success" or results[0]["exit_code"] != 0:
        raise ValueError("expected one successful scripted worker result")
    score = grade(results[0]["findings"], json.loads(catalog), json.loads(receipt))
    score["sha256"] = {
        name: hashlib.sha256(data).hexdigest()
        for name, data in (("catalog", catalog), ("receipt", receipt), ("transcript", transcript))
    }
    print(json.dumps(score, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
