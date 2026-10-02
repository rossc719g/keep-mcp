import asyncio
import inspect
import json
import warnings
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import gkeepapi
import pytest
import requests

from server import cli, credentials, keep_api, runtime, setup, storage
from server.safety import (
    DeleteChallenges,
    label_revision,
    note_revision,
)


@pytest.fixture
def real_keep(monkeypatch):
    keep = gkeepapi.Keep()
    keep.sync = Mock()
    monkeypatch.setattr(cli, "get_client", lambda: keep)
    return keep


def ai_note(keep):
    note = keep.createNote("private-title-marker", "private-content-marker")
    note.labels.add(keep.findLabel("AI") or keep.createLabel("AI"))
    return note


def test_keychain_only_ignores_env_backend_and_path(monkeypatch):
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyrings.alt.file.PlaintextKeyring")
    monkeypatch.setenv("KEYCHAIN_PATH", "/tmp/not-a-keychain")
    monkeypatch.setattr(credentials.sys, "platform", "darwin")
    from keyring.backends.macOS import Keyring

    backend = credentials.keychain()
    assert type(backend) is Keyring
    assert backend.keychain is None


def test_no_plaintext_fallback_on_other_platform(monkeypatch):
    monkeypatch.setattr(credentials.sys, "platform", "linux")
    with pytest.raises(ValueError, match="No plaintext fallback"):
        credentials.keychain()


def test_credential_roundtrip_only_email_on_disk(monkeypatch, tmp_path):
    vault = {}
    backend = SimpleNamespace(
        set_password=lambda service, account, secret: vault.update(
            {(service, account): secret}
        ),
        get_password=lambda service, account: vault.get((service, account)),
    )
    monkeypatch.setattr(credentials, "keychain", lambda: backend)
    credentials.store_credentials("test@example.com", "secret-master-marker")
    assert credentials.account_email() == "test@example.com"
    assert credentials.master_token("test@example.com") == "secret-master-marker"
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert "secret-master-marker" not in path.read_text()
            assert path.stat().st_mode & 0o777 == 0o600


def test_dotenv_never_loaded_and_environment_token_rejected(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "GOOGLE_MASTER_TOKEN=secret-master-marker\nGOOGLE_EMAIL=test@example.com\n"
    )
    with pytest.raises(ValueError, match="not configured"):
        credentials.account_email()
    monkeypatch.setenv("GOOGLE_MASTER_TOKEN", "secret-master-marker")
    with pytest.raises(ValueError) as caught:
        credentials.account_email()
    assert "Remove GOOGLE_MASTER_TOKEN" in str(caught.value)
    assert "secret-master-marker" not in str(caught.value)


def test_keychain_failure_hides_exception_details(monkeypatch):
    backend = SimpleNamespace(
        get_password=Mock(side_effect=RuntimeError("secret-master-marker"))
    )
    monkeypatch.setattr(credentials, "keychain", lambda: backend)
    with pytest.raises(ValueError) as caught:
        credentials.master_token("test@example.com")
    assert "Keychain" in str(caught.value)
    assert "secret-master-marker" not in str(caught.value)


def test_setup_checks_credentials_before_keychain_write(monkeypatch):
    monkeypatch.setattr(
        setup.sys, "argv", ["keep-mcp-setup", "token", "--email", "test@example.com"]
    )
    monkeypatch.setattr(setup.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(setup.getpass, "getpass", lambda _: "secret-master-marker")
    store = Mock()
    monkeypatch.setattr(setup, "store_credentials", store)
    monkeypatch.setattr(
        setup, "check_credentials", Mock(side_effect=storage.SafetyError("Rejected"))
    )
    with pytest.raises(SystemExit):
        setup.main()
    store.assert_not_called()


def test_setup_refuses_getpass_fallback_that_would_echo(monkeypatch):
    def no_hidden_input(prompt):
        warnings.warn("Cannot control echo", setup.getpass.GetPassWarning, stacklevel=2)
        pytest.fail("An echoed credential prompt must never be reached")

    monkeypatch.setattr(setup.getpass, "getpass", no_hidden_input)
    with pytest.raises(ValueError, match="must never be echoed"):
        setup.read_secret("Token: ")


@pytest.mark.parametrize(
    "error, expected",
    [
        ("BadAuthentication", "BadAuthentication"),
        ("NeedsBrowser", "NeedsBrowser"),
        ("CaptchaRequired", "CaptchaRequired"),
        ("InvalidSecondFactor", "InvalidSecondFactor"),
        ("MissingDroidguard", "MissingDroidguard"),
        ("ServiceDisabled", "ServiceDisabled"),
        ("AccountDisabled", "AccountDisabled"),
        (None, "UnrecognizedResponse"),
        ("BadAuthentication secret-response-marker", "UnrecognizedResponse"),
        ({"unexpected": "secret-response-marker"}, "UnrecognizedResponse"),
    ],
)
def test_setup_exchange_error_redacts_response_and_does_not_store(
    monkeypatch, capsys, error, expected
):
    monkeypatch.setattr(
        setup.sys, "argv", ["keep-mcp-setup", "exchange", "--email", "test@example.com"]
    )
    monkeypatch.setattr(setup.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(setup.getpass, "getpass", lambda _: "secret-browser-marker")
    exchange = Mock(
        return_value={
            "Error": error,
            "ErrorDetail": "secret-response-marker",
            "Url": "https://accounts.google.com/secret-response-marker",
            "Auth": "secret-response-marker",
        }
    )
    monkeypatch.setattr(setup.gpsoauth, "exchange_token", exchange)
    store, check = Mock(), Mock()
    monkeypatch.setattr(setup, "store_credentials", store)
    monkeypatch.setattr(setup, "check_credentials", check)
    with pytest.raises(SystemExit) as caught:
        setup.main()
    assert caught.value.code == 1
    output = capsys.readouterr()
    assert f"({expected})" in output.err
    assert "No credential was saved" in output.err
    assert "secret-" not in output.out + output.err
    exchange.assert_called_once()
    check.assert_not_called()
    store.assert_not_called()


def test_setup_exchange_exception_never_exposes_credentials(monkeypatch, capsys):
    monkeypatch.setattr(
        setup.sys, "argv", ["keep-mcp-setup", "exchange", "--email", "test@example.com"]
    )
    monkeypatch.setattr(setup.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(setup.getpass, "getpass", lambda _: "secret-browser-marker")
    exchange = Mock(side_effect=RuntimeError("secret-browser-marker"))
    monkeypatch.setattr(setup.gpsoauth, "exchange_token", exchange)
    store = Mock()
    monkeypatch.setattr(setup, "store_credentials", store)
    with pytest.raises(SystemExit):
        setup.main()
    output = capsys.readouterr()
    assert "Google token exchange failed" in output.err
    assert "secret-browser-marker" not in output.out + output.err
    exchange.assert_called_once()
    store.assert_not_called()


@pytest.mark.parametrize(
    "error, code",
    [
        (gkeepapi.exception.LoginException("BadAuthentication"), "BadAuthentication"),
        (
            gkeepapi.exception.BrowserLoginRequiredException("secret-url-marker"),
            "NeedsBrowser",
        ),
        (
            gkeepapi.exception.LoginException("secret-token-marker"),
            "UnrecognizedResponse",
        ),
        (gkeepapi.exception.APIException(403, "secret-note-marker"), "HTTP_403"),
        (
            requests.HTTPError(
                "secret-token-marker", response=SimpleNamespace(status_code=401)
            ),
            "HTTP_401",
        ),
        (requests.Timeout("secret-token-marker"), "NetworkTimeout"),
        (requests.ConnectionError("secret-token-marker"), "NetworkConnectionFailed"),
        (requests.exceptions.SSLError("secret-token-marker"), "TLSFailure"),
        (
            gkeepapi.exception.ParseException("secret-note-marker", {"text": "secret"}),
            "ParseException",
        ),
        (
            gkeepapi.exception.UpgradeRecommendedException("secret"),
            "UpgradeRecommendedException",
        ),
        (
            gkeepapi.exception.ResyncRequiredException("secret"),
            "ResyncRequiredException",
        ),
        (KeyError("secret-note-marker"), "KeyError"),
        (TypeError("secret-note-marker"), "TypeError"),
        (ValueError("secret-note-marker"), "ValueError"),
        (AttributeError("secret-note-marker"), "AttributeError"),
        (RuntimeError("secret-token-marker"), "UnrecognizedResponse"),
    ],
)
@pytest.mark.parametrize("failing_stage", ["Keep authorization", "Initial Keep read"])
def test_setup_identifies_failing_stage_without_exposing_data(
    monkeypatch, error, code, failing_stage
):
    keep = Mock()
    if failing_stage == "Keep authorization":
        keep.authenticate.side_effect = error
    else:
        keep.sync.side_effect = error
    monkeypatch.setattr(setup.gkeepapi, "Keep", lambda: keep)
    with pytest.raises(storage.SafetyError) as caught:
        setup.check_credentials("test@example.com", "secret-master-marker")
    message = str(caught.value)
    assert message.startswith(f"{failing_stage} failed ({code}).")
    assert "secret" not in message
    keep.authenticate.assert_called_once_with(
        "test@example.com", "secret-master-marker", sync=False
    )
    if failing_stage == "Keep authorization":
        keep.sync.assert_not_called()
    else:
        keep.sync.assert_called_once_with()


@pytest.mark.parametrize("failure", [None, "authorization", "read"])
def test_setup_real_client_validates_authorization_and_read_before_storing(
    monkeypatch, capsys, failure
):
    monkeypatch.setattr(
        setup.sys, "argv", ["keep-mcp-setup", "exchange", "--email", "test@example.com"]
    )
    monkeypatch.setattr(setup.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(setup.getpass, "getpass", lambda _: "secret-browser-marker")
    monkeypatch.setattr(
        setup.gpsoauth,
        "exchange_token",
        Mock(return_value={"Token": "secret-master-marker"}),
    )
    oauth = Mock(
        return_value={"Error": "NeedsBrowser"}
        if failure == "authorization"
        else {"Auth": "secret-access-marker"}
    )
    monkeypatch.setattr(setup.gpsoauth, "perform_oauth", oauth)
    read = Mock(return_value={"toVersion": "1", "truncated": False})
    if failure == "read":
        read.side_effect = requests.HTTPError(
            "secret-response-marker", response=SimpleNamespace(status_code=403)
        )
    monkeypatch.setattr(keep_api.BoundedKeepAPI, "changes", read)

    def store_after_read(email, token):
        oauth.assert_called_once()
        read.assert_called_once_with(target_version=None, nodes=[], labels=None)
        assert (email, token) == ("test@example.com", "secret-master-marker")

    store = Mock(side_effect=store_after_read)
    monkeypatch.setattr(setup, "store_credentials", store)
    if failure:
        with pytest.raises(SystemExit):
            setup.main()
        store.assert_not_called()
    else:
        setup.main()
        store.assert_called_once()
    output = capsys.readouterr()
    assert "secret-" not in output.out + output.err
    assert "Token exchange succeeded" in output.out
    if failure == "authorization":
        assert "Keep authorization failed (NeedsBrowser)" in output.err
        read.assert_not_called()
    elif failure == "read":
        assert "Initial Keep read failed (HTTP_403)" in output.err


def test_http_failures_never_replay_keep_requests(monkeypatch):
    api = keep_api.BoundedKeepAPI()
    response = Mock()
    response.raise_for_status.side_effect = requests.HTTPError("private-content-marker")
    send = Mock(return_value=response)
    monkeypatch.setattr(api, "_send", send)
    with pytest.raises(requests.HTTPError):
        api.send(method="POST", json={"nodes": []})
    send.assert_called_once()


def test_network_policy_keeps_tls_verified_and_stops_redirects(monkeypatch):
    request = Mock()
    monkeypatch.setattr(requests.Session, "request", request)
    session = keep_api.BoundedSession()
    session.get("https://keep.google.com/test", verify=False, allow_redirects=True)
    assert session.trust_env is False
    assert request.call_args.kwargs["verify"] is True
    assert request.call_args.kwargs["allow_redirects"] is False
    assert request.call_args.kwargs["timeout"] == (10, 30)


def test_reads_allowed_for_unlabelled_notes(real_keep):
    note = real_keep.createNote("ordinary", "all reads are allowed")
    assert json.loads(cli.get_note(note.id))["text"] == note.text
    assert any(result["id"] == note.id for result in json.loads(cli.find()))


def test_intent_required_for_creation_and_edits(real_keep):
    note = ai_note(real_keep)
    with pytest.raises(ValueError, match="explicit user request"):
        cli.update_note(note.id, title="no", expected_revision=note_revision(note))
    with pytest.raises(ValueError, match="explicit user request"):
        cli.create_note("no")
    assert note.title == "private-title-marker"
    assert len(real_keep.all()) == 1


NOTE_WRITES = [
    ("update_note", {"title": "no"}),
    ("add_list_item", {"text": "no"}),
    ("update_list_item", {"item_id": "x", "text": "no"}),
    ("delete_list_item", {"item_id": "x"}),
    ("set_note_color", {"color": "RED"}),
    ("pin_note", {}),
    ("archive_note", {}),
    ("trash_note", {}),
    ("restore_note", {}),
    ("delete_note", {}),
    ("add_label_to_note", {"label_id": "x"}),
    ("remove_label_from_note", {"label_id": "x"}),
    ("add_note_collaborator", {"email": "sensitive-email@example.com"}),
    ("remove_note_collaborator", {"email": "sensitive-email@example.com"}),
]


@pytest.mark.parametrize("name,arguments", NOTE_WRITES)
def test_all_existing_note_writes_require_ai_even_with_unsafe_mode(
    real_keep, monkeypatch, name, arguments
):
    note = real_keep.createNote("ordinary", "unchanged")
    note.labels.add(real_keep.createLabel("keep-mcp"))
    monkeypatch.setenv("UNSAFE_MODE", "true")
    with pytest.raises(ValueError, match='exact "AI" label'):
        getattr(cli, name)(
            note.id,
            **arguments,
            expected_revision=note_revision(note),
            user_requested=True,
        )
    assert note.text == "unchanged"


@pytest.mark.parametrize("name,arguments", NOTE_WRITES)
def test_all_existing_note_writes_reject_stale_revisions(real_keep, name, arguments):
    note = ai_note(real_keep)
    before = note_revision(note)
    note.text = "changed in Keep"
    with pytest.raises(ValueError, match="Conflict"):
        getattr(cli, name)(
            note.id, **arguments, expected_revision=before, user_requested=True
        )
    assert note.text == "changed in Keep"


def test_change_observed_during_preflight_sync_rejects_write(real_keep):
    note = ai_note(real_keep)
    before = json.loads(cli.get_note(note.id))["revision"]
    real_keep.sync.side_effect = lambda: setattr(note, "text", "new remote value")
    with pytest.raises(ValueError, match="Conflict"):
        cli.update_note(
            note.id,
            text="stale overwrite",
            expected_revision=before,
            user_requested=True,
        )
    assert note.text == "new remote value"


def test_revision_covers_checklist_children_and_ignores_dirty_bits(real_keep):
    note = real_keep.createList("list", [("one", False)])
    note.labels.add(real_keep.createLabel("AI"))
    initial = note_revision(note)
    note.save()
    for item in note.items:
        item.save()
    assert note_revision(note) == initial
    note.items[0].checked = True
    assert note_revision(note) != initial


def test_mcp_cannot_add_ai_to_an_unmanaged_note(real_keep):
    note = real_keep.createNote("ordinary", "text")
    label = real_keep.createLabel("AI")
    with pytest.raises(ValueError, match="cannot grant itself access"):
        cli.add_label_to_note(
            note.id,
            label.id,
            expected_revision=note_revision(note),
            user_requested=True,
        )
    assert not note.labels.all()


def test_new_notes_and_lists_receive_ai(real_keep):
    assert "AI" in [
        label["name"]
        for label in json.loads(cli.create_note("new", user_requested=True))["labels"]
    ]
    assert "AI" in [
        label["name"]
        for label in json.loads(cli.create_list("new list", user_requested=True))[
            "labels"
        ]
    ]


def test_label_deletion_checks_all_affected_notes_and_revision(real_keep):
    note = ai_note(real_keep)
    label = real_keep.createLabel("shared")
    note.labels.add(label)
    before = label_revision(real_keep, label)
    note.text = "remote change"
    with pytest.raises(ValueError, match="Conflict"):
        cli.delete_label(label.id, expected_revision=before, user_requested=True)
    ordinary = real_keep.createNote("ordinary", "text")
    ordinary.labels.add(label)
    with pytest.raises(ValueError, match='without the "AI" label'):
        cli.delete_label(
            label.id,
            expected_revision=label_revision(real_keep, label),
            user_requested=True,
        )


def test_delete_requires_two_calls_explicit_permanent_and_single_use(real_keep):
    note = ai_note(real_keep)
    revision = note_revision(note)
    first = json.loads(
        cli.delete_note(
            note.id,
            expected_revision=revision,
            user_requested=True,
            permanently_delete=True,
        )
    )
    assert first["status"] == "confirmation_required"
    assert "archive_note" in first["message"] and "60 seconds" in first["message"]
    assert not note.deleted
    token = first["confirmation_token"]
    cli.delete_note(
        note.id,
        expected_revision=revision,
        user_requested=True,
        permanently_delete=True,
        confirmation_token=token,
    )
    assert note.deleted
    with pytest.raises(ValueError):
        cli.delete_note(
            note.id,
            expected_revision=note_revision(note),
            user_requested=True,
            permanently_delete=True,
            confirmation_token=token,
        )


def test_delete_challenge_expiry_target_binding_and_no_automatic_confirmation():
    now = [100.0]
    challenges = DeleteChallenges(clock=lambda: now[0])
    original = ("note", "1", "rev")
    first = challenges.confirm(original, None, False)
    with pytest.raises(ValueError):
        challenges.confirm(original, first["confirmation_token"], False)
    fresh = challenges.confirm(original, None, False)
    with pytest.raises(ValueError):
        challenges.confirm(("note", "2", "rev"), fresh["confirmation_token"], True)
    expired = challenges.confirm(original, None, False)
    now[0] += 60
    with pytest.raises(ValueError, match="expired"):
        challenges.confirm(original, expired["confirmation_token"], True)


def test_changed_note_invalidates_destructive_confirmation(real_keep):
    note = ai_note(real_keep)
    revision = note_revision(note)
    first = json.loads(
        cli.delete_note(note.id, expected_revision=revision, user_requested=True)
    )
    note.text = "remote change"
    with pytest.raises(ValueError, match="Conflict"):
        cli.delete_note(
            note.id,
            expected_revision=revision,
            user_requested=True,
            permanently_delete=True,
            confirmation_token=first["confirmation_token"],
        )
    assert not note.deleted


def test_audit_contains_metadata_without_content_and_appends(real_keep):
    note = ai_note(real_keep)
    cli.pin_note(note.id, expected_revision=note_revision(note), user_requested=True)
    path = storage.state_directory() / "mutations.jsonl"
    first = path.read_bytes()
    cli.archive_note(
        note.id, expected_revision=note_revision(note), user_requested=True
    )
    contents = path.read_bytes()
    assert contents.startswith(first)
    records = [json.loads(line) for line in contents.splitlines()]
    assert [r["status"] for r in records] == [
        "started",
        "succeeded",
        "started",
        "succeeded",
    ]
    assert all(r["note_id_hash"] != note.id for r in records)
    assert (
        b"private-content-marker" not in contents
        and b"private-title-marker" not in contents
    )
    assert path.stat().st_mode & 0o777 == 0o600


def test_audit_failure_blocks_mutation_before_upload(real_keep, monkeypatch):
    note = ai_note(real_keep)
    monkeypatch.setattr(runtime, "append_audit", Mock(side_effect=OSError("disk full")))
    with pytest.raises(ValueError, match="No edit was sent"):
        cli.pin_note(
            note.id, expected_revision=note_revision(note), user_requested=True
        )
    assert not note.pinned


def test_final_audit_failure_reports_completed_edit_without_retry(
    real_keep, monkeypatch
):
    note = ai_note(real_keep)
    append = runtime.append_audit
    calls = []

    def fail_outcome(record):
        calls.append(record)
        if len(calls) > 1:
            raise OSError("disk full")
        append(record)

    monkeypatch.setattr(runtime, "append_audit", fail_outcome)
    with pytest.raises(ValueError, match="operation completed"):
        cli.pin_note(
            note.id, expected_revision=note_revision(note), user_requested=True
        )
    assert note.pinned
    assert real_keep.sync.call_count == 2
    records = [
        json.loads(line)
        for line in (storage.state_directory() / "mutations.jsonl")
        .read_text()
        .splitlines()
    ]
    assert [record["status"] for record in records] == ["started"]


def test_failed_sync_discards_dirty_client_and_never_retries(real_keep, monkeypatch):
    note = ai_note(real_keep)
    keep_api._keep_client = real_keep
    real_keep.sync.side_effect = [
        None,
        RuntimeError("secret-master-marker private-content-marker"),
    ]
    with pytest.raises(ValueError, match="unknown") as caught:
        cli.update_note(
            note.id,
            text="pending",
            expected_revision=note_revision(note),
            user_requested=True,
        )
    assert keep_api._keep_client is None
    assert real_keep.sync.call_count == 2
    assert "secret-master-marker" not in str(caught.value)
    assert (
        "secret-master-marker"
        not in (storage.state_directory() / "mutations.jsonl").read_text()
    )
    replacement = gkeepapi.Keep()
    replacement.sync = Mock()
    monkeypatch.setattr(cli, "get_client", lambda: replacement)
    assert json.loads(cli.find()) == []
    assert real_keep.sync.call_count == 2


def test_audit_and_media_symlink_paths_fail_closed(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("keep this")
    path = storage.state_directory() / "mutations.jsonl"
    path.symlink_to(outside)
    with pytest.raises(OSError):
        storage.append_audit({"operation": "test"})
    assert outside.read_text() == "keep this"
    with pytest.raises(ValueError):
        storage.export_directory(str(tmp_path))
    with pytest.raises(ValueError):
        storage.export_directory("../outside")


def test_media_download_cannot_overwrite_or_escape(real_keep, monkeypatch, tmp_path):
    note = ai_note(real_keep)
    blob = SimpleNamespace(
        id="test", blob=SimpleNamespace(type=SimpleNamespace(value="IMAGE"))
    )
    monkeypatch.setattr(type(note), "blobs", property(lambda _: [blob]))
    monkeypatch.setattr(cli, "fetch_blob_bytes", lambda *a: (b"bytes", "image/png"))
    first = json.loads(cli.download_media(note.id, "test", user_requested=True))
    path = Path(first[0]["path"])
    assert path.read_bytes() == b"bytes"
    with pytest.raises(ValueError):
        cli.download_media(note.id, "test", user_requested=True)
    assert path.read_bytes() == b"bytes"
    with pytest.raises(ValueError):
        cli.download_media(note.id, str(tmp_path), user_requested=True)


@pytest.mark.parametrize(
    "url",
    [
        "http://keep.google.com/x",
        "https://evil.example/x",
        "https://googleusercontent.com.evil.example/x",
        "https://user:secret@keep.google.com/x",
        "https://127.0.0.1/x",
    ],
)
def test_media_host_policy_rejects_untrusted_urls(url):
    with pytest.raises(ValueError):
        keep_api.validate_media_url(url)


def test_mcp_schema_advertises_guards_and_reads():
    tools = asyncio.run(cli.mcp.list_tools())
    by_name = {tool.name: tool.model_dump(by_alias=True) for tool in tools}
    assert len(by_name) == 24
    for name, _ in NOTE_WRITES:
        assert "expected_revision" in by_name[name]["inputSchema"]["required"]
        assert by_name[name]["annotations"]["readOnlyHint"] is False
        assert (
            by_name[name]["inputSchema"]["properties"]["user_requested"]["default"]
            is False
        )
    assert by_name["get_note"]["annotations"]["readOnlyHint"] is True
    assert by_name["add_note_collaborator"]["annotations"]["openWorldHint"] is True
    assert "confirmation_token" in inspect.signature(cli.delete_note).parameters
    assert "confirmation_token" in inspect.signature(cli.delete_list_item).parameters
