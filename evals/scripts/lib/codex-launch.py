"""Pass API authentication to Codex without putting its value in argv."""

import os
import sys


with os.fdopen(3, encoding="utf-8") as stream:
    api_key = stream.read().strip()
if not api_key:
    sys.exit("missing explicit Scourge eval API key")

command = sys.argv[1:]
os.execve(command[0], command, {**os.environ, "CODEX_API_KEY": api_key})
