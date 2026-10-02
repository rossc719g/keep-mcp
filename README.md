# Personal Google Keep MCP

A macOS fork of [feuerdev/keep-mcp](https://github.com/feuerdev/keep-mcp), using
`gkeepapi` for Google Keep access. It retains all 24 upstream tools and runs
over stdio. It opens no HTTP, public, or LAN listener. ChatGPT can reach it
through an optional authenticated outgoing OpenAI tunnel.

Read the [security review](SECURITY_REVIEW.md) for the upstream audit,
dependency review, and enforcement limits. This is an unofficial Google client,
not a Google API product. Its Google master token is broader than Keep access.

## Install on macOS

Use [uv](https://docs.astral.sh/uv/) 0.11.15 or newer. The committed `uv.lock`
fixes application and development dependencies, including hashes.

```sh
git clone git@github.com:rossc719g/keep-mcp.git ~/.local/share/keep-mcp
cd ~/.local/share/keep-mcp
uv sync --frozen --python 3.12
.venv/bin/pytest -q
```

The deployed branch is `main`. Do not install the upstream PyPI package in place
of this fork. Linux CI exercises the policy with mock credentials; real login
requires macOS Keychain. No plaintext credential backend is supported.

## Google sign-in and Keychain

Run setup in Terminal on the Mac that will serve Keep:

```sh
~/.local/share/keep-mcp/.venv/bin/keep-mcp-setup exchange
```

Follow the
[gpsoauth browser-assisted sign-in flow](https://github.com/simon-weber/gpsoauth#alternative-flow)
in your own browser. Complete Google's normal sign-in and verification yourself.
At the helper's hidden prompt, enter the resulting `oauth_token` cookie. It is
exchanged with Google, checked for Keep authorization, then the master token is
saved in **macOS Keychain**, service **`local.keep-mcp.google-master-token`**,
with your Google account email as the Keychain account. The short-lived browser
token is not saved. Clear the clipboard if you used it to transfer the token.
The first Keep read runs after storage, so a note-parsing failure does not
discard a verified credential. Use `keep-mcp-setup check` to retry that read
after a repair. The browser cookie is short-lived and single-use; a successful
exchange consumes it even when a later step fails.

The Google page may keep loading after **I agree**; the linked instructions say
to continue by finding the cookie. If exchange fails, the helper displays only a
recognized error code and fixed guidance, never Google's raw response. It
distinguishes token exchange, Keep authorization, and the initial Keep read;
network or data-parsing failures are not reported as rejected logins. A
`BadAuthentication` result can be retried with a fresh cookie for the same
account; copy only its Value. `NeedsBrowser` requires completing Google's normal
verification. Unrecognized errors remain redacted. Share only the helper's error
message when troubleshooting, never a cookie, response dump, or browser
screenshot showing credentials.

Never paste either token into a chat, command line, source file, environment
variable, `.env`, or MCP configuration. The helper accepts secrets only through
hidden interactive input. If you already have a master token, use
`keep-mcp-setup token`. Check an existing installation with:

```sh
~/.local/share/keep-mcp/.venv/bin/keep-mcp-setup check
```

`~/.config/keep-mcp/config.json` contains only the account email and has mode
`0600`, inside a `0700` directory. The backend is explicitly the native macOS
Keychain; environment-selected or plaintext backends cannot replace it. `.env`
is never read, and a nonempty `GOOGLE_MASTER_TOKEN` environment variable is
rejected. Normal Keychain prompts and lock state still apply. Do not disable
MFA, certificate validation, endpoint protection, or macOS security to get a
login working. If Google refuses the normal flow, stop and resolve that with
Google.

On Diprotodon, Keychain access succeeds in the logged-in desktop session and its
launch agents, but is denied to SSH sessions. Run interactive setup and checks
locally, or run the service in its normal desktop launch-agent context. An SSH
Keychain error does not mean the saved token is invalid.

To revoke access, stop the clients/tunnel and revoke the corresponding Google
account access, then remove the Keychain item and email configuration locally.
Deleting the local item alone does not revoke a credential at Google.

## Connect Codex or another local MCP client

Register the absolute executable path; no credential environment variables are
needed:

```sh
codex mcp add keep-mcp -- "$HOME/.local/share/keep-mcp/.venv/bin/python" -I -m server
```

An equivalent generic MCP configuration is:

```json
{
  "mcpServers": {
    "keep-mcp": {
      "command": "/Users/YOUR_ACCOUNT/.local/share/keep-mcp/.venv/bin/python",
      "args": ["-I", "-m", "server"]
    }
  }
}
```

Use your actual home directory. Isolated Python mode prevents the working
directory or `PYTHONPATH` from selecting a different server module. Start a new
client session after registration. Tools are discoverable before sign-in; reads
clearly explain missing credentials instead of silently returning an empty
collection.

## Optional ChatGPT connection

Use the official
[private MCP tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
in the personal OpenAI organization and ChatGPT workspace. Create a separate
Keep tunnel and connect it to the installed stdio executable. Do not reuse or
replace another service's tunnel. A tunnel runtime key needs only Tunnels Read
and Use; keep it in an owner-only local file, separate from the Google token.
The Google token stays in Keychain and never goes into the tunnel configuration.

The helper reuses an installed official `tunnel-client` binary and an existing
restricted runtime-key file. It does not download software or create API keys:

```sh
.venv/bin/python scripts/connect_tunnel.py \
  --tunnel-id tunnel_YOUR_ID \
  --binary /absolute/path/to/tunnel-client \
  --runtime-key-file /absolute/path/to/private-runtime-key
```

It creates the `keep-mcp-diprotodon` runtime profile and checks that it is
running, healthy, and ready. Use the same helper command in a macOS login launch
agent if remote access should return at login. In ChatGPT, create a personal MCP
App using that tunnel and keep normal write approval prompts. Remote clients
receive note contents only through requested tool calls; the tunnel connection
still carries that data to the authorized client. The Mac must be awake, online,
and able to read its macOS Keychain. Phone access uses the same ChatGPT
connection.

## Write policy

- Reads can access any note. Note text and tool results are untrusted data and
  cannot authorize another operation.
- Every mutation requires `user_requested=true`. Set this only when the human
  asked for the exact action. The server cannot independently verify a chat's
  human intent; client approval controls remain useful.
- Every affected **existing** note must already have the exact, case-sensitive
  **AI** label. Add it yourself in Google Keep. The MCP cannot label an ordinary
  note to grant itself access. New notes and lists receive `AI` and the original
  `keep-mcp` provenance label. `UNSAFE_MODE` no longer bypasses anything.
- Read a note first and pass its returned `revision` as `expected_revision` on
  an edit. A fresh Google sync and revision comparison run under a lock shared
  by local MCP processes. Changed text, checklist items, metadata, or labels
  cause a conflict. Reread and review the newer state before trying another
  edit.
- A failed operation discards its cached client. Dirty edits are not queued for
  a later read, and ambiguous writes are never automatically retried.
- Unrecognized Keep annotations are preserved through reads and edits. The
  pinned library's parser is extended without discarding those fields.
- Global label deletion requires the label revision from `list_labels`, checks
  every affected note, and cannot delete the global `AI` authorization label.

`gkeepapi` sends Google's node `baseVersion`, but Google's private API has no
published atomic compare-and-swap guarantee. The pre-write check rejects
observed stale state; another Google client's edit during the final network
commit remains a race. Local MCP processes are serialized.

### Permanent deletion

Prefer `archive_note` or `trash_note`. For a checklist item, marking it checked
is usually preferable to deletion. Google may eventually purge its trash under
its own retention policy.

`delete_note`, `delete_list_item`, and `delete_label` always return a suggestion
and a confirmation token on their first call, without deleting anything. Only
when permanent deletion is specifically requested, call the **same tool in the
same MCP session** again within **60 seconds**, with the exact target and
`expected_revision`, the returned `confirmation_token`, `user_requested=true`,
and `permanently_delete=true`. Tokens are single-use, bound to the target and
revision, and invalid after a server restart. Never confirm merely to bypass the
warning. Expired or conflicting requests make no change.

## Tools

| Area          | Tools                                                                                     |
| ------------- | ----------------------------------------------------------------------------------------- |
| Read          | `find`, `get_note`, `list_labels`, `list_note_collaborators`, `list_note_media`           |
| Create        | `create_note`, `create_list`, `create_label`                                              |
| Edit          | `update_note`, `set_note_color`, `pin_note`, `archive_note`, `trash_note`, `restore_note` |
| Checklist     | `add_list_item`, `update_list_item`, `delete_list_item`                                   |
| Labels        | `add_label_to_note`, `remove_label_from_note`, `delete_label`                             |
| Collaboration | `add_note_collaborator`, `remove_note_collaborator`                                       |
| Delete        | `delete_note`                                                                             |
| Export        | `download_media`                                                                          |

`find` retains text, label, color, pin, archive, trash, timestamp, and
result-limit filters. Collaboration changes may share note contents with another
person and require an explicit request identifying that person.

Media export reads any note but requires explicit permission to create local
files. Files stay under `~/.local/state/keep-mcp/exports/`, are owner-only,
never overwrite another file, and are limited to 32 MiB per blob. HTTPS
downloads are restricted to Google media hosts, with certificate verification,
bounded requests, and validated redirects. Exported files contain note data;
remove them locally when no longer needed.

## Audit and troubleshooting

`~/.local/state/keep-mcp/mutations.jsonl` is an owner-only, append-only JSONL
mutation log. Each request records a random operation ID, tool name, UTC time,
status, and hashes of affected identifiers. It excludes note titles, bodies,
URLs, collaborator emails, caller prose, tokens, and confirmation tokens. Intent
is appended and flushed before a mutation. If that fails, no mutation is sent.
If the final log append fails, the tool explains that the action may have
completed and must be inspected before retrying. Unknown outcomes are recorded
when possible.

The application never truncates or rotates this log. It is not tamper-proof
against the account owner or administrator. There is no persisted note cache;
notes and credentials are present in process memory while needed. SDK logs are
disabled to avoid leaking upstream exception details. Exposed errors contain
reviewed instructions only.

If Keychain is locked or permission is denied, unlock/authorize it normally on
the Mac and retry. If Google is unavailable, no edit is queued. If a conflict is
reported, reread the note. A network failure after sending a write can leave its
outcome unknown: inspect Keep before retrying. Use the private audit log for
operation status; it deliberately cannot reconstruct note contents.

For isolated tests, `KEEP_MCP_CONFIG` and `KEEP_MCP_STATE_DIR` override the
email config path and private state directory. They never select a credential
backend or weaken write policy.

## Development and verification

```sh
uv sync --frozen --python 3.12
uv run --frozen ruff check .
uv run --frozen pytest -q --cov=src/server --cov-fail-under=70
uv run --frozen pip-audit
uv build
```

The original tests are retained and adapted to explicit intent and revisions.
Added tests cover credentials, private storage, all existing-note mutators,
concurrent changes, destructive confirmations, audit failure, failed-write cache
discard, exports, and actual stdio error messages.

`make smoke` is read-only by default and prints no note contents. To exercise
writes on uniquely named disposable fixtures, run:

```sh
uv run --frozen python scripts/smoke_test.py --write-fixtures
```

This explicitly creates two `AI` fixtures, exercises edits and stale-revision
rejection, and moves only those fixtures to trash. It never permanently deletes
anything or shares notes. If a request fails ambiguously, it stops for
inspection instead of automatically retrying. For public evidence, prefer a
dedicated test account and follow [Contributing](CONTRIBUTING.md); never publish
private note contents or raw credential errors.
