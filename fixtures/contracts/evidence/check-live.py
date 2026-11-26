"""Qualify the entire frozen evidence fixture through the Investigation adapter."""

import json
import sys
import unittest
from pathlib import Path

from run import EvidenceCases, adapter_factory

FIXTURE = Path(__file__).resolve().parent
SUCCESS = "Investigation public-interface: 12 passed, 0 failed, 0 skipped"


def qualify(cases, expected):
    loader = unittest.TestLoader()
    names = loader.getTestCaseNames(cases)
    if len(expected) != 12 or names != expected:
        print("Investigation conformance case inventory mismatch", file=sys.stderr)
        return 1
    result = unittest.TextTestRunner(verbosity=2).run(loader.loadTestsFromTestCase(cases))
    if (
        result.testsRun != len(expected)
        or not result.wasSuccessful()
        or result.skipped
        or result.expectedFailures
    ):
        print("Investigation conformance requires every assigned case to pass", file=sys.stderr)
        return 1
    print(SUCCESS, flush=True)
    return 0


def main():
    record = json.loads((FIXTURE / "investigation-conformance.json").read_text())

    class NativeCases(EvidenceCases):
        driver_factory = staticmethod(adapter_factory(FIXTURE / "investigation.py"))

    return qualify(NativeCases, record["result"]["cases"])


if __name__ == "__main__":
    sys.exit(main())
