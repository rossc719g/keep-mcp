# Personal fork security review

Reviewed October 1, 2026, before changing runtime behavior. Upstream:
[`feuerdev/keep-mcp` at `12fa3ec`](https://github.com/feuerdev/keep-mcp/tree/12fa3ec1412077a1236bdd8c39c835a7daec34ad).
All 53 original tests passed on macOS with Python 3.12 and 3.14. The source,
authentication and media paths, all tool handlers, tests, build configuration,
and CI/release workflows were inspected.

## Findings and decisions

| Finding                                                                                                                              | Required change                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The master token is loaded from `.env` or environment variables. Login errors include upstream exception text.                       | Use the macOS Keychain backend explicitly, with no plaintext fallback. Keep credential entry out of MCP and sanitize upstream errors.                                               |
| `UNSAFE_MODE` bypasses the label boundary; callers need not assert user intent.                                                      | Remove the bypass. Require explicit user intent on every mutation and the exact `AI` label on every existing note affected.                                                         |
| The cached client is not refreshed for each tool call. There is no expected-version check.                                           | Synchronize before reads and writes; require a returned revision for every existing-note mutation. Serialize local operations across processes.                                     |
| An exception can leave dirty cached objects to be uploaded by a later sync.                                                          | Discard the client after failed operations; never retry ambiguous writes.                                                                                                           |
| `delete_note` immediately calls `delete()`. Label deletion may affect many notes.                                                    | Prefer archive/trash. Require a short-lived, single-use challenge bound to the exact target and revision for permanent deletion. Validate every affected note when deleting labels. |
| Mutations leave no audit trail.                                                                                                      | Append and flush intent before a write and its outcome afterward, using an owner-only local log. Omit note text, titles, email addresses, URLs, credentials, and caller prose.      |
| Media downloads accept arbitrary output paths, overwrite existing files, and follow authenticated media URLs without a local policy. | Confine downloads to private export storage, prevent overwrites and symlinks, and bound HTTPS downloads to Google media hosts.                                                      |
| Dependencies have broad lower bounds and no lockfile. The upstream release workflow publishes on pushes to main.                     | Pin and lock the tested dependency graph. Restrict release publishing to upstream.                                                                                                  |

## Dependencies

The initial resolution uses `gkeepapi 0.17.1`, `gpsoauth 2.0.0`, `mcp 2.2.0`,
and `requests 2.34.2`. Their authentication, sync, mutation serialization,
request/retry, and media code was inspected. The selected Keychain adapter is
`keyring 25.7.0`'s explicit macOS backend, which calls Security.framework.
Dynamic backend selection and plaintext backends are not used. Keyring 25.7 uses
SecItem APIs and ignores custom keychain paths; the adapter explicitly clears
`KEYCHAIN_PATH` selection and uses the normal macOS user Keychain. A new-item
test through SSH returned macOS status -25308 (interaction not allowed).
Credential setup runs in the user's local Terminal and honors normal Keychain
prompts. Live verification subsequently confirmed that a launch agent in the
logged-in desktop session can read the saved credential and authorize Keep,
while the SSH session cannot. No Keychain permissions or security settings were
relaxed.

The first advisory scan found the same pip advisory twice (`PYSEC-2026-3721` /
`CVE-2026-13346`) in the development interpreter's `pip 26.1.2`; no application
dependency advisory was reported. That isolated development installer was
upgraded to 26.2.1. Diprotodon's environment also resolved pip 26.2.1.

`gkeepapi` is an unofficial Google client and its master token is broader than
Keep. The implementation retains certificate verification and normal macOS
Keychain controls. Authentication failures must not recommend disabling MFA,
device management, endpoint protection, or other security settings.

## Scope and limits

The existing stdio transport is retained: no public or LAN listener. Optional
ChatGPT access uses a separately authorized authenticated outgoing tunnel. The
existing `gkeepapi` operations and serializers are retained behind a shared
policy boundary rather than replaced with a second Google client.

An MCP caller can assert user intent; the server cannot independently prove what
a human said in a chat. The `AI` boundary, required revisions, and deletion
challenges are enforced in code even if a caller ignores tool instructions.

The revision check detects changes observed during the pre-write sync, and
`gkeepapi` sends Google's `baseVersion` for persisted nodes. The private API
does not provide a documented transactional compare-and-swap contract; edits
made in another Google client during the network commit remain a limitation.
This must not be described as a distributed transaction guarantee.

The local audit is append-only through this application, not immutable against
the Mac's account owner or administrator. Notes and credentials are held in
process memory while in use; the service does not persist a note cache.

## Verification

165 tests pass on both the development Mac and Diprotodon (Python 3.14.6 and
3.12.13), including the original cases adapted to the guarded API. Final source
coverage on D is 93%. Dependency scans report no known vulnerabilities. Tests
cover the real stdio MCP handshake and actionable credential errors; token
redaction; Keychain-only selection; every existing-note write boundary; stale
versions; cross-process locking; deletion expiry, target binding and reuse;
failed-write cache discard; audit failure; and media containment. A wheel and
source distribution build successfully.

Live Google authorization and read synchronization passed from the desktop
session. Real stdio MCP checks passed for creation, editing, stale-revision
rejection, color, pinning, archive/unarchive, trash/restore, and checklist
edits. All three disposable notes created across setup checks were left in
recoverable trash; no permanent deletion or collaboration changes were exercised
live. ChatGPT connected through the private tunnel and discovered 5 read and 19
write tools. Phone interaction and a full Mac reboot were not independently
tested.

The initial read exposed a gkeepapi 0.17.1 bug: its annotation factory returns
`None` for unknown types, then the container dereferences `annotation.id`. The
compatibility adapter extends that existing factory and preserves unknown
annotations as opaque data, including nested context entries, instead of
dropping them. Regression tests verify round-trip retention through edits and
revision checks. Setup now stores a credential after Google authorizes Keep,
before the first read, so a parser error cannot discard a verified login. Safe
diagnostics include only an allowlisted error category and module/line location;
credentials, note contents, raw responses, and exception text remain hidden.
