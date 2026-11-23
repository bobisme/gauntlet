#!/usr/bin/env python3
"""Check cleanup on interruption before a container ID is available."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


class CleanupTest(unittest.TestCase):
    def test_interrupted_run_removes_unique_container_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "podman"
            fake.write_text('''#!/usr/bin/python3
import os, pathlib, sys, time
args = sys.argv[1:]
root = pathlib.Path(os.environ["TEST_BOUNDARY_ROOT"])
assert args.pop(0) == "--remote=false"
if args[0] == "info": print("true")
elif args[:2] == ["image", "inspect"]: print("a" * 64)
elif args[0] == "--version": print("test podman")
elif args[0] == "run":
    name = args[args.index("--name") + 1]
    (root / "started").write_text(name)
    time.sleep(60)
elif args[0] == "rm": (root / "removed").write_text(args[-1])
elif args[:2] == ["container", "exists"]:
    assert (root / "removed").read_text() == args[-1]
    sys.exit(1)
else: sys.exit(2)
''')
            fake.chmod(0o755)
            files = [root / str(i) for i in range(3)]
            for file in files:
                file.write_text("private")
            env = dict(os.environ, PATH=f"{root}:/usr/bin:/bin", TEST_BOUNDARY_ROOT=tmp)
            helper = Path(__file__).resolve().parent / "lib/boundary.py"
            child = subprocess.Popen([sys.executable, "-I", str(helper), "http://127.0.0.1:1",
                                      *(str(file) for file in files)], env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 10
                while not (root / "started").exists() and time.monotonic() < deadline:
                    self.assertIsNone(child.poll())
                    time.sleep(0.05)
                self.assertTrue((root / "started").exists())
                child.terminate()
                child.wait(timeout=10)
                self.assertNotEqual(child.returncode, 0)
                self.assertEqual((root / "started").read_text(), (root / "removed").read_text())
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()


if __name__ == "__main__":
    unittest.main()
