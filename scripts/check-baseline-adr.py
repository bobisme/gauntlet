#!/usr/bin/env python3
"""Require one explicit ADR disposition for every row of the plan tables."""

from collections import Counter
from pathlib import Path
import re
import sys


SECTIONS = (
    ("### 5.4 Obligations", ("Obligation", "How it is met"), "## Proof obligations", "Obligation"),
    ("## 13. Invariants", ("ID", "Invariant", "Enforced by"), "## Invariants", "Invariant"),
    ("## 14. Fixture catalog", ("ID", "Situation", "Required behavior"), "## Fixtures", "Fixture"),
)
ROOT = Path(__file__).resolve().parents[1]
HEADING = re.compile(r" {0,3}#{1,6}(?:[ \t]|$)")
PIPE = re.compile(r"(?<!\\)\|")
DELIMITER = re.compile(r":?-+:?")
FENCE = re.compile(r" {0,3}(?:(`{3,})[^`]*|(~{3,}).*)$")
COMMENT_OPEN = re.compile(r" {0,3}<!--")
COMMENT_CLOSE = re.compile(r"-->")


def table_cells(line):
    cells = PIPE.split(line.strip())
    if cells[0] == "":
        cells = cells[1:]
    if cells and cells[-1] == "":
        cells = cells[:-1]
    return tuple(cell.strip() for cell in cells)


def wrapped_lines(lines):
    """Find lines inside top-level fenced code blocks or HTML comments."""
    closing = None
    for index, line in enumerate(lines):
        if closing is not None:
            yield index
            if closing.search(line):
                closing = None
        elif COMMENT_OPEN.match(line):
            yield index
            if not COMMENT_CLOSE.search(line):
                closing = COMMENT_CLOSE
        elif (fence := FENCE.match(line)) is not None:
            yield index
            marker = fence[1] or fence[2]
            closing = re.compile(rf"^ {{0,3}}{marker[0]}{{{len(marker)},}}[\t ]*$")


def table_rows(markdown, heading, header):
    lines = markdown.splitlines()
    wrapped = set(wrapped_lines(lines))
    headings = [
        index for index, line in enumerate(lines)
        if index not in wrapped and HEADING.match(line) and line.strip() == heading
    ]
    if len(headings) != 1:
        raise ValueError(f"expected one section {heading!r}")
    start = headings[0] + 1
    end = next(
        (
            index for index in range(start, len(lines))
            if index not in wrapped and HEADING.match(lines[index])
        ),
        len(lines),
    )
    if any(index in wrapped or "<!--" in lines[index] for index in range(start, end)):
        raise ValueError(f"{heading}: code fences and HTML comments cannot wrap table content")
    # A pipe row after a blank line or other block is outside the named table.
    row_indices = [index for index in range(start, end) if PIPE.search(lines[index])]
    if len(row_indices) < 3:
        raise ValueError(f"missing or empty table under {heading!r}")
    if row_indices != list(range(row_indices[0], row_indices[-1] + 1)):
        raise ValueError(f"{heading}: expected one contiguous table")
    before, after = row_indices[0] - 1, row_indices[-1] + 1
    # GFM can render adjacent prose as a table row with missing cells.
    if lines[before].strip(" \t") or (after < len(lines) and lines[after].strip(" \t")):
        raise ValueError(f"{heading}: the table must have a blank line on each side")

    rows = []
    for index in row_indices:
        line = lines[index]
        indent = line[:len(line) - len(line.lstrip(" \t"))]
        if len(indent.expandtabs(4)) > 3:
            raise ValueError(f"{heading}: table row at line {index + 1} is indented as code")
        cells = table_cells(line)
        if len(cells) != len(header):
            raise ValueError(
                f"{heading}: table row at line {index + 1} has {len(cells)} cells "
                f"(expected {len(header)})"
            )
        rows.append(cells)
    if rows[0] != header or not all(DELIMITER.fullmatch(cell) for cell in rows[1]):
        raise ValueError(f"{heading}: invalid table header or delimiter")
    return rows[2:]


def unique_keys(rows, heading):
    keys = [row[0] for row in rows]
    duplicates = sorted(key for key, count in Counter(keys).items() if count > 1)
    if "" in keys or duplicates:
        raise ValueError(f"{heading}: empty or duplicate row keys: {duplicates}")
    return set(keys)


def check_dispositions(rows, heading, allowed):
    for key, disposition, reason in rows:
        if disposition not in allowed or not reason:
            raise ValueError(f"{heading}: {key} needs a disposition and reason")


def check_coverage(plan, adr):
    counts = []
    for source, source_header, destination, key_label in SECTIONS:
        expected = unique_keys(table_rows(plan, source, source_header), source)
        rows = table_rows(adr, destination, (key_label, "Disposition", "Reason"))
        actual = unique_keys(rows, destination)
        if expected != actual:
            raise ValueError(
                f"{destination}: missing {sorted(expected - actual)}, "
                f"unexpected {sorted(actual - expected)}"
            )
        check_dispositions(rows, destination, {"KEEP", "CUT"})
        counts.append(len(expected))

    additions_heading = "## Added acceptance"
    additions = table_rows(
        adr, additions_heading, ("Addition", "Disposition", "Requirement and evidence")
    )
    for key in sorted(unique_keys(additions, additions_heading)):
        if not re.fullmatch(r"M0-ADD-[0-9]{2}", key):
            raise ValueError(f"{additions_heading}: invalid addition ID {key!r}")
    check_dispositions(additions, additions_heading, {"ADD"})
    counts.append(len(additions))
    return counts


def main():
    try:
        obligations, invariants, fixtures, additions = check_coverage(
            (ROOT / "notes/plan.md").read_text(encoding="utf-8"),
            (ROOT / "docs/adr/baseline-taxonomy-decision.md").read_text(encoding="utf-8"),
        )
    except (OSError, ValueError) as error:
        print(f"baseline ADR coverage: {error}", file=sys.stderr)
        return 1
    print(
        f"baseline ADR coverage: {obligations} obligations, {invariants} invariants, "
        f"{fixtures} fixtures, {additions} additions"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
