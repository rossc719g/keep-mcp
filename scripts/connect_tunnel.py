"""Connect the installed stdio server through the existing official tunnel client."""

import argparse
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path

ALIAS = "keep-mcp-diprotodon"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tunnel-id", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--runtime-key-file", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"tunnel_[A-Za-z0-9_-]{10,100}", args.tunnel_id):
        parser.error("Invalid tunnel identifier")
    key = args.runtime_key_file.expanduser().absolute()
    info = key.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        parser.error("Runtime key must be an owner-only regular file")
    binary = args.binary.expanduser().absolute()
    command = shlex.join([sys.executable, "-m", "server"])
    env = dict(os.environ)
    env.pop("CONTROL_PLANE_API_KEY", None)
    env.pop("GOOGLE_MASTER_TOKEN", None)
    result = subprocess.run(
        [
            str(binary),
            "runtimes",
            "connect",
            "--alias",
            ALIAS,
            "--profile",
            ALIAS,
            "--tunnel-id",
            args.tunnel_id,
            "--mcp-command",
            command,
            "--runtime-api-key",
            "file:" + str(key),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode:
        raise SystemExit(
            "Keep tunnel could not connect. Check the private runtime logs and runtime key permissions; no credentials are printed."
        )
    status = subprocess.run(
        [str(binary), "runtimes", "status", ALIAS, "--json"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if status.returncode:
        raise SystemExit("Keep tunnel connected but its status could not be checked.")
    data = json.loads(status.stdout)
    summary = {
        "alias": ALIAS,
        "tunnel_id": args.tunnel_id,
        "running": data.get("process_running") is True,
        "healthy": data.get("healthy") is True,
        "ready": data.get("ready") is True,
    }
    print(json.dumps(summary))
    if not all(summary[field] for field in ("running", "healthy", "ready")):
        raise SystemExit(
            "Keep tunnel is not ready. Check the private runtime status before connecting ChatGPT."
        )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit(
            "Keep tunnel setup did not complete. Inspect the private local configuration; no credentials are printed."
        ) from None
