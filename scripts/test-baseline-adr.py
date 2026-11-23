#!/usr/bin/env python3
"""Exercise coverage checks against single-row edits of the real tables."""

from pathlib import Path
from runpy import run_path
import re
import unittest


SCRIPTS = Path(__file__).resolve().parent
CHECK = run_path(str(SCRIPTS / "check-baseline-adr.py"))["check_coverage"]
ROOT = SCRIPTS.parent
WRAPPERS = (("~~~", "~~~"), ("```markdown", "```"), ("<!--", "-->"))


class CoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = (ROOT / "notes/plan.md").read_text(encoding="utf-8")
        cls.adr = (ROOT / "docs/adr/baseline-taxonomy-decision.md").read_text(encoding="utf-8")
        cls.fixture_row = next(line for line in cls.adr.splitlines() if line.startswith("| F-53 |"))
        cls.plan_row = next(line for line in cls.plan.splitlines() if line.startswith("| F-53 |"))

    def check_row_edit(self, replacement):
        return CHECK(self.plan, self.adr.replace(self.fixture_row, replacement, 1))

    def test_committed_tables(self):
        self.assertEqual(CHECK(self.plan, self.adr), [11, 51, 53, 4])

    def test_original_mutation_cases(self):
        row = self.fixture_row
        cases = {
            "missing": ("", "missing ['F-53']"),
            "duplicate": (row + "\n" + row, "duplicate row keys: ['F-53']"),
            "unexpected": (row.replace("F-53", "F-99"), "unexpected ['F-99']"),
            "wrong action": (row.replace("| KEEP |", "| ADD |"), "needs a disposition"),
            "empty reason": ("| F-53 | KEEP | |", "needs a disposition"),
        }
        for name, (replacement, error) in cases.items():
            with self.subTest(case=name), self.assertRaisesRegex(ValueError, re.escape(error)):
                self.check_row_edit(replacement)
        self.assertEqual(self.check_row_edit(row.replace("| KEEP |", "| CUT |")), [11, 51, 53, 4])
        with self.assertRaisesRegex(ValueError, r"missing \['F-54'\]"):
            CHECK(self.plan.replace("| F-53 |", "| F-54 |", 1), self.adr)

    def test_indented_duplicate(self):
        row = self.fixture_row
        with self.assertRaisesRegex(ValueError, r"duplicate row keys: \['F-53'\]"):
            self.check_row_edit(row + "\n  " + row)

    def test_indented_undisposed_plan_row(self):
        extra = self.plan_row + "\n   | F-54 | Another scenario. | Another behavior. |"
        with self.assertRaisesRegex(ValueError, r"missing \['F-54'\]"):
            CHECK(self.plan.replace(self.plan_row, extra, 1), self.adr)

    def test_extra_cell_cannot_supply_reason(self):
        with self.assertRaisesRegex(ValueError, r"has 4 cells \(expected 3\)"):
            self.check_row_edit("| F-53 | KEEP | | Extra cell |")

    def test_blank_line_splits_table(self):
        for separator in ("\n", "  \n"):
            with self.subTest(separator=separator), self.assertRaisesRegex(
                ValueError, "expected one contiguous table"
            ):
                self.check_row_edit(separator + self.fixture_row)

    def test_prose_adjacent_to_table(self):
        header = "| Fixture | Disposition | Reason |"
        prose = "This prose would be another row."
        edits = {
            "before": self.adr.replace(header, prose + "\n" + header, 1),
            "after": self.adr.replace(self.fixture_row, self.fixture_row + "\n" + prose, 1),
        }
        for boundary, adr in edits.items():
            with self.subTest(boundary=boundary), self.assertRaisesRegex(
                ValueError, "table must have a blank line on each side"
            ):
                CHECK(self.plan, adr)
        self.assertEqual(
            self.check_row_edit(self.fixture_row + "\n\n" + prose),
            [11, 51, 53, 4],
        )

    def test_fence_or_comment_in_table_section(self):
        header = "| Fixture | Disposition | Reason |"
        start = self.adr.index(header)
        end = self.adr.index(self.fixture_row) + len(self.fixture_row)
        table = self.adr[start:end]
        for opener, closer in WRAPPERS:
            with self.subTest(wrapper=opener), self.assertRaisesRegex(
                ValueError, "code fences and HTML comments"
            ):
                wrapped = f"{opener}\n\n{table}\n\n{closer}"
                CHECK(self.plan, self.adr[:start] + wrapped + self.adr[end:])
        with self.assertRaisesRegex(ValueError, "code fences and HTML comments"):
            self.check_row_edit("| F-53 | KEEP | <!-- Hidden reason. --> |")

    def test_fence_or_comment_hiding_section_heading(self):
        start = self.adr.index("## Proof obligations")
        end = self.adr.index("## Invariants", start)
        section = self.adr[start:end]
        for opener, closer in WRAPPERS:
            with self.subTest(wrapper=opener), self.assertRaisesRegex(
                ValueError, "expected one section '## Proof obligations'"
            ):
                wrapped = f"{opener}\n\n{section}{closer}\n\n"
                CHECK(self.plan, self.adr[:start] + wrapped + self.adr[end:])

    def test_indentation_and_literal_pipe(self):
        for indent in (" ", "  ", "   "):
            with self.subTest(indent=indent):
                reason = r"Text with \| in the reason."
                self.assertEqual(
                    self.check_row_edit(f"{indent}F-53 | KEEP | {reason}"),
                    [11, 51, 53, 4],
                )
        for indent in ("    ", "\t", "  \t"):
            with self.subTest(indent=indent), self.assertRaisesRegex(
                ValueError, "indented as code"
            ):
                self.check_row_edit(indent + self.fixture_row)


if __name__ == "__main__":
    unittest.main()
