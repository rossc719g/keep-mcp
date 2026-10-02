import asyncio
import os
import subprocess
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from server.storage import operation_lock, state_directory


@pytest.mark.parametrize("environment_token", [False, True])
def test_stdio_errors_are_actionable_without_credentials(environment_token, tmp_path):
    async def check():
        env = dict(os.environ)
        (tmp_path / "server.py").write_text('raise RuntimeError("wrong server module")')
        env["PYTHONPATH"] = str(tmp_path)
        if environment_token:
            env["GOOGLE_MASTER_TOKEN"] = "secret-transport-marker"
        with (tmp_path / "stderr").open("w+") as errors:
            async with stdio_client(
                StdioServerParameters(
                    command=sys.executable,
                    args=["-I", "-m", "server"],
                    env=env,
                    cwd=str(tmp_path),
                ),
                errlog=errors,
            ) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    assert len((await session.list_tools()).tools) == 24
                    result = await session.call_tool("find", {"limit": 1})
                    assert result.is_error
                    message = " ".join(item.text for item in result.content)
                    assert "secret-transport-marker" not in message
                    if environment_token:
                        assert "Remove GOOGLE_MASTER_TOKEN" in message
                    else:
                        assert "not configured" in message
                        assert "keep-mcp-setup" in message
            errors.seek(0)
            assert "secret-transport-marker" not in errors.read()

    asyncio.run(check())


def test_operation_lock_serializes_separate_mcp_processes():
    script = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(7)
sys.exit(0)
"""
    command = [sys.executable, "-c", script, str(state_directory() / "operation.lock")]
    with operation_lock():
        assert subprocess.run(command, timeout=10).returncode == 7
    assert subprocess.run(command, timeout=10).returncode == 0
