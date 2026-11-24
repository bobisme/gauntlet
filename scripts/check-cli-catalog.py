#!/usr/bin/env python3
"""Check the fixed Scourge vocabulary in CLI help and presentation strings."""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYNONYMS = re.compile(
    r"\b(?:candidates?|hypothesis|hypotheses|issues?|attempts?|cases?|verdicts?|conclusions?)\b",
    re.IGNORECASE,
)
# Rust CLI help is written in doc comments, attributes and ordinary/raw string
# literals. Ignore ordinary comments. SQL/data and tests live outside this scan.
CATALOG = re.compile(
    r'(?m)^[ \t]*///(?P<doc>[^\n]*)|//[^\n]*|'
    r'r(?P<hash>\#*)"(?P<raw>.*?)"(?P=hash)|"(?P<text>(?:\\.|[^"\\])*)"',
    re.DOTALL,
)
NATIVE_OWNER = re.compile(
    r"\bteapot(?:['’]s(?:\s+own)?|\s*[:–-]|\s+(?:has|holds|reported|records))\s*"
    r"(?:(?:\d+|an?|the)\s+)?(?:finding|lead)s?\b",
    re.IGNORECASE,
)
NATIVE_CASE = re.compile(r"\b(?i:teapot)\s+(?i:findings?|leads?)\b")
QUALIFIED = re.compile(r"Teapot (?:finding|lead)s?\b")


def violations(catalog):
    for synonym in SYNONYMS.findall(catalog):
        yield f"use a Scourge noun in place of {synonym!r}"
    for owner in NATIVE_OWNER.findall(catalog):
        yield f"qualify the instrument noun in {owner!r} as Teapot finding or Teapot lead"
    for mention in NATIVE_CASE.findall(catalog):
        if not QUALIFIED.fullmatch(mention):
            yield f"use Teapot finding or Teapot lead in place of {mention!r}"


def check_sources():
    failures = []
    for source in sorted((ROOT / "crates/scourge/src").rglob("*.rs")):
        text = source.read_text()
        for match in CATALOG.finditer(text):
            catalog = match["doc"] or match["raw"] or match["text"]
            if catalog:
                if match["text"] is not None:
                    catalog = re.sub(r"\\[nrt]|\\\n[ \t]*", " ", catalog)
                line = text.count("\n", 0, match.start()) + 1
                failures.extend(f"{source.relative_to(ROOT)}:{line}: {error}" for error in violations(catalog))
    return failures


def main():
    for sample in ("candidate", "HYPOTHESES", "issues", "attempt", "cases", "verdict", "conclusions", "Teapot's findings", "Teapot: 5 leads", "Teapot reported a finding", "teapot lead"):
        assert list(violations(sample)), sample
    assert not list(violations("A Teapot finding and Teapot leads can become Scourge leads. Show the engagement, experiment, finding or run."))
    failures = check_sources()
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
