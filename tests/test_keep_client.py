from types import SimpleNamespace

from server import keep_api


class DummyKeep:
    def __init__(self):
        self.auth_calls = []
        self._media_api = SimpleNamespace()

    def authenticate(self, email, token):
        self.auth_calls.append((email, token))


def test_get_client_authenticates_and_caches(monkeypatch):
    keep_api._keep_client = None
    created = DummyKeep()

    monkeypatch.setattr(keep_api, "account_email", lambda: "user@example.com")
    monkeypatch.setattr(keep_api, "master_token", lambda email: "token")
    monkeypatch.setattr(keep_api.gkeepapi, "Keep", lambda: created)

    first = keep_api.get_client()
    second = keep_api.get_client()

    assert first is created
    assert second is created
    assert created.auth_calls == [("user@example.com", "token")]


def test_get_client_raises_when_missing_credentials(monkeypatch):
    keep_api._keep_client = None

    try:
        keep_api.get_client()
    except ValueError as exc:
        assert "not configured" in str(exc)
    else:
        raise AssertionError("Expected ValueError for missing credentials")
