"""Regression checks for owned group teardown with harmless local processes."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


LIB = Path(__file__).resolve().parent / "lib"


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="scourge-supervisor-")
        self.addCleanup(temporary.cleanup)
        self.run = Path(temporary.name)
        self.prefix = self.run / "owned"

    def start_supervisor(self, *command, limit=10):
        supervisor = subprocess.Popen([
            sys.executable, "-I", str(LIB / "supervise.py"), str(os.getpid()),
            str(limit), str(self.prefix), "0", *command,
        ])

        def stop():
            self.prefix.with_suffix(".stop").touch()
            supervisor.wait(timeout=6)

        self.addCleanup(stop)
        return supervisor

    def start_unrelated_group(self):
        unrelated = subprocess.Popen(["/usr/bin/sleep", "30"], start_new_session=True)

        def stop():
            unrelated.terminate()
            unrelated.wait(timeout=2)

        self.addCleanup(stop)
        return unrelated

    def command_exit(self):
        status = self.prefix.with_suffix(".exit")
        deadline = time.monotonic() + 5
        while not status.is_file() and time.monotonic() < deadline:
            time.sleep(0.02)
        return int(status.read_text(encoding="ascii"))

    def test_command_exits_first_and_supervisor_reaps_its_group(self):
        unrelated = self.start_unrelated_group()
        child_pid_file = self.run / "child-pid"
        supervisor = self.start_supervisor(sys.executable, "-I", "-c", (
            "from pathlib import Path\n"
            "import subprocess, sys\n"
            "child = subprocess.Popen(['/usr/bin/sleep', '30'])\n"
            "Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii')\n"
        ), str(child_pid_file))

        self.assertEqual(self.command_exit(), 0)
        descendant = int(child_pid_file.read_text(encoding="ascii"))
        self.assertIsNone(supervisor.poll())
        self.assertEqual(os.getpgid(descendant), supervisor.pid)
        self.prefix.with_suffix(".stop").touch()

        self.assertEqual(supervisor.wait(timeout=5), 0)
        self.assertEqual(self.prefix.with_suffix(".stopped").read_text(), "clean\n")
        with self.assertRaises(ProcessLookupError):
            os.getpgid(descendant)
        self.assertIsNone(unrelated.poll())

    def test_stale_group_id_never_signals_an_unrelated_group(self):
        unrelated = self.start_unrelated_group()
        # Simulate a reused numeric PGID with no corresponding owned supervisor.
        completed = subprocess.run([
            "/bin/bash", "-p", "-c", 'source "$1"; stop_process_group "$2" "$3"',
            "bash", str(LIB / "common.sh"), str(self.prefix), str(unrelated.pid),
        ], timeout=5)
        self.assertEqual(completed.returncode, 1)
        self.assertIsNone(unrelated.poll())

    def test_command_timeout_stops_the_owned_group(self):
        supervisor = self.start_supervisor("/usr/bin/sleep", "30", limit=1)
        self.assertEqual(self.command_exit(), 124)
        self.assertEqual(supervisor.wait(timeout=5), 0)
        self.assertEqual(self.prefix.with_suffix(".stopped").read_text(), "clean\n")


if __name__ == "__main__":
    unittest.main()
