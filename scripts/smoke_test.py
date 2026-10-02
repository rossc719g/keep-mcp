"""Exercise the real stdio transport without printing private Keep data."""

import argparse
import asyncio
import json
import sys
import uuid

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def run(write_fixtures):
    async with stdio_client(
        StdioServerParameters(command=sys.executable, args=["-I", "-m", "server"])
    ) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            assert len((await session.list_tools()).tools) == 24

            async def call(name, **arguments):
                result = await session.call_tool(name, arguments)
                if result.is_error:
                    raise RuntimeError(
                        "Keep smoke request failed. Inspect the private audit log and the test fixtures before retrying; nothing is retried automatically."
                    )
                return json.loads(result.content[0].text)

            await call("find", limit=1)
            print("Read synchronization through the MCP connection succeeded.")
            if not write_fixtures:
                return
            marker = "Keep MCP test " + uuid.uuid4().hex[:12]
            note = await call(
                "create_note",
                title=marker,
                text="Disposable setup fixture",
                user_requested=True,
            )
            original = note["revision"]
            note = await call(
                "update_note",
                note_id=note["id"],
                text="Updated fixture",
                expected_revision=original,
                user_requested=True,
            )
            stale = await session.call_tool(
                "update_note",
                {
                    "note_id": note["id"],
                    "text": "Must not overwrite",
                    "expected_revision": original,
                    "user_requested": True,
                },
            )
            assert stale.is_error and "Conflict" in stale.content[0].text
            for name, extra in [
                ("set_note_color", {"color": "BLUE"}),
                ("pin_note", {"pinned": True}),
                ("archive_note", {"archived": True}),
                ("archive_note", {"archived": False}),
                ("trash_note", {}),
                ("restore_note", {}),
                ("trash_note", {}),
            ]:
                note = await call(
                    name,
                    note_id=note["id"],
                    expected_revision=note["revision"],
                    user_requested=True,
                    **extra,
                )
            checklist = await call(
                "create_list",
                title=marker + " list",
                items=[{"text": "Disposable item", "checked": False}],
                user_requested=True,
            )
            checklist = await call(
                "update_list_item",
                note_id=checklist["id"],
                item_id=checklist["items"][0]["id"],
                checked=True,
                expected_revision=checklist["revision"],
                user_requested=True,
            )
            await call(
                "trash_note",
                note_id=checklist["id"],
                expected_revision=checklist["revision"],
                user_requested=True,
            )
            print(
                "Fixture writes, stale-revision rejection, and recoverable cleanup succeeded."
            )
            print(
                "Two uniquely named test notes remain in Google Keep trash. Nothing was permanently deleted."
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-fixtures",
        action="store_true",
        help="Explicitly authorize creating, editing, and trashing two disposable test notes.",
    )
    args = parser.parse_args()
    try:
        asyncio.run(run(args.write_fixtures))
    except Exception:
        print(
            "Smoke test did not complete. Use keep-mcp-setup check; inspect fixture state and the private audit before retrying.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
