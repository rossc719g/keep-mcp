# Personal fork security review

Reviewed October 1, 2026, before changing runtime behavior. Upstream:
[`feuerdev/keep-mcp` at `12fa3ec`](https://github.com/feuerdev/keep-mcp/tree/12fa3ec1412077a1236bdd8c39c835a7daec34ad).
All 53 original tests passed on macOS with Python 3.12 and 3.14. The source,
authentication and media paths, all tool handlers, tests, build configuration,
and CI/release workflows were inspected.

## Findings and decisions

| Finding | Required change |
| --- | --- |
| The master token is loaded from `.env` or environment variables. Login errors include upstream exception text. | Use the macOS Keychain backend explicitly, with no plaintext fallback. Keep credential entry out of MCP and sanitize upstream errors. |
| `UNSAFE_MODE` bypasses the label boundary; callers need not assert user intent. | Remove the bypass. Require explicit user intent on every mutation and the exact `AI` label on every existing note affected. |
| The cached client is not refreshed for each tool call. There is no expected-version check. | Synchronize before reads and writes; require a returned revision for every existing-note mutation. Serialize local operations across processes. |
| An exception can leave dirty cached objects to be uploaded by a later sync. | Discard the client after failed operations; never retry ambiguous writes. |
| `delete_note` immediately calls `delete()`. Label deletion may affect many notes. | Prefer archive/trash. Require a short-lived, single-use challenge bound to the exact target and revision for permanent deletion. Validate every affected note when deleting labels. |
| Mutations leave no audit trail. | Append and flush intent before a write and its outcome afterward, using an owner-only local log. Omit note text, titles, email addresses, URLs, credentials, and caller prose. |
| Media downloads accept arbitrary output paths, overwrite existing files, and follow authenticated media URLs without a local policy. | Confine downloads to private export storage, prevent overwrites and symlinks, and bound HTTPS downloads to Google media hosts. |
| Dependencies have broad lower bounds and no lockfile. The upstream release workflow publishes on pushes to main. | Pin and lock the tested dependency graph. Restrict release publishing to upstream. |

## Dependencies

The initial resolution uses `gkeepapi 0.17.1`, `gpsoauth 2.0.0`, `mcp 2.2.0`,
and `requests 2.34.2`. Their authentication, sync, mutation serialization,
request/retry, and media code was inspected. The selected Keychain adapter is
`keyring 25.7.0`'s explicit macOS backend, which calls Security.framework.
Dynamic backend selection and plaintext backends will not be used.

The first advisory scan found the same pip advisory twice
(`PYSEC-2026-3721` / `CVE-2026-13346`) in the development interpreter's
`pip 26.1.2`; no application dependency advisory was reported. That isolated
development installer is being upgraded to 26.2.1. Diprotodon's environment
already resolved pip 26.2.1. Record the final locked scan below after testing.

`gkeepapi` is an unofficial Google client and its master token is broader than
Keep. The implementation will retain certificate verification and normal macOS
Keychain controls. Authentication failures must not recommend disabling MFA,
device management, endpoint protection, or other security settings.

## Scope and limits

The existing stdio transport is retained: no public or LAN listener. Optional
ChatGPT access uses a separately authorized authenticated outgoing tunnel.
The existing `gkeepapi` operations and serializers are retained behind a shared
policy boundary rather than replaced with a second Google client.

An MCP caller can assert user intent; the server cannot independently prove
what a human said in a chat. The `AI` boundary, required revisions, and deletion
challenges are enforced in code even if a caller ignores tool instructions.

The revision check detects changes observed during the pre-write sync, and
`gkeepapi` sends Google's `baseVersion` for persisted nodes. The private API
does not provide a documented transactional compare-and-swap contract; edits
made in another Google client during the network commit remain a limitation.
This must not be described as a distributed transaction guarantee.

The local audit is append-only through this application, not immutable against
the Mac's account owner or administrator. Notes and credentials are held in
process memory while in use; the service does not persist a note cache.
