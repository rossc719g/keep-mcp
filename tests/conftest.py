import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch, tmp_path):
    from server import keep_api
    from server.safety import delete_challenges

    monkeypatch.setenv("KEEP_MCP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("KEEP_MCP_CONFIG", str(tmp_path / "config" / "config.json"))
    monkeypatch.delenv("GOOGLE_MASTER_TOKEN", raising=False)
    keep_api.discard_client()
    delete_challenges.pending.clear()
    yield
    keep_api.discard_client()


def requested(function, *args, **kwargs):
    """Adapt upstream happy-path calls to the read-then-explicit-write contract."""
    import inspect
    import json

    from server import cli

    parameters = inspect.signature(function).parameters
    kwargs["user_requested"] = True
    if "expected_revision" in parameters:
        if "note_id" in parameters:
            try:
                kwargs["expected_revision"] = json.loads(cli.get_note(args[0]))[
                    "revision"
                ]
            except ValueError:
                kwargs["expected_revision"] = "missing"
        else:
            kwargs["expected_revision"] = next(
                (
                    label["revision"]
                    for label in json.loads(cli.list_labels())
                    if label["id"] == args[0]
                ),
                "missing",
            )
    return function(*args, **kwargs)
