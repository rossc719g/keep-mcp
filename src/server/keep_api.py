from urllib.parse import urlsplit

import gkeepapi
import requests

from .credentials import account_email, master_token
from .safety import can_modify_note as can_modify_note
from .safety import note_revision
from .storage import SafetyError

KEEP_MCP_LABEL = "keep-mcp"

_keep_client = None


def discard_client():
    global _keep_client
    _keep_client = None


def get_client():
    global _keep_client
    if _keep_client is not None:
        return _keep_client
    email = account_email()
    token = master_token(email)
    keep = gkeepapi.Keep()
    keep._keep_api = BoundedKeepAPI()
    keep._media_api._session = BoundedSession()
    try:
        keep.authenticate(email, token)
    except Exception:
        raise SafetyError(
            "Google Keep authentication failed. Run keep-mcp-setup check locally. "
            "Complete any Google verification normally; do not disable MFA or device security."
        ) from None
    finally:
        del token
    _keep_client = keep
    return keep


class BoundedSession(requests.Session):
    def __init__(self):
        super().__init__()
        self.trust_env = False

    def request(self, method, url, **kwargs):
        validate_media_url(url)
        kwargs["timeout"] = (10, 30)
        kwargs["allow_redirects"] = False
        kwargs["verify"] = True
        return super().request(method, url, **kwargs)


class BoundedKeepAPI(gkeepapi.KeepAPI):
    def __init__(self):
        super().__init__()
        self._session = BoundedSession()

    def send(self, **kwargs):
        # A single attempt avoids replaying a mutation after an ambiguous failure.
        response = self._send(**kwargs)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or "error" in data:
            raise RuntimeError("Google response did not confirm success")
        return data


def serialize_label(label):
    return {"id": label.id, "name": label.name}


def serialize_list_item(item):
    return {
        "id": item.id,
        "text": item.text,
        "checked": item.checked,
        "parent_item_id": item.parent_item.id if item.parent_item else None,
    }


def serialize_note(note):
    """
    Serialize a Google Keep note into a dictionary.

    Args:
        note: A Google Keep note object

    Returns:
        dict: A dictionary containing the note's id, title, text, pinned status, color and labels
    """
    timestamps = getattr(note, "timestamps", None)
    created = getattr(timestamps, "created", None)
    updated = getattr(timestamps, "updated", None)

    payload = {
        "id": note.id,
        "revision": note_revision(note),
        "title": note.title,
        "text": note.text,
        "type": note.type.value,
        "pinned": note.pinned,
        "archived": note.archived,
        "trashed": note.trashed,
        "color": note.color.value if note.color else None,
        "created": created.isoformat() if created else None,
        "updated": updated.isoformat() if updated else None,
        "labels": [serialize_label(label) for label in note.labels.all()],
        "collaborators": list(note.collaborators.all()),
    }

    if hasattr(note, "items"):
        payload["items"] = [serialize_list_item(item) for item in note.items]

    payload["media"] = [
        {
            "blob_id": blob.id,
            "type": blob.blob.type.value if blob.blob and blob.blob.type else None,
        }
        for blob in note.blobs
    ]

    return payload


_MEDIA_EXTENSIONS = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "audio/3gpp": ".3gp",
    "audio/amr": ".amr",
    "audio/mpeg": ".mp3",
}


def media_extension(content_type):
    """
    Map a media response Content-Type to a file extension.

    Args:
        content_type: The Content-Type header value (may carry parameters)

    Returns:
        str: A dotted extension, '.bin' when the type is unknown or missing
    """
    if not content_type:
        return ".bin"
    return _MEDIA_EXTENSIONS.get(content_type.split(";")[0].strip().lower(), ".bin")


def validate_media_url(url):
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or not (
            host in {"keep.google.com", "notes-pa.googleapis.com", "www.googleapis.com"}
            or host.endswith(".googleusercontent.com")
        )
    ):
        raise SafetyError(
            "Refusing a media URL outside the allowed Google HTTPS hosts."
        )


def fetch_blob_bytes(keep, blob):
    url = keep.getMediaLink(blob)
    validate_media_url(url)
    media = keep._media_api
    for _ in range(5):
        with media._send(
            url=url, method="GET", stream=True, allow_redirects=False, timeout=(10, 30)
        ) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                from urllib.parse import urljoin

                url = urljoin(url, response.headers["Location"])
                validate_media_url(url)
                continue
            if response.status_code in (400, 401, 403):
                with media._session.get(
                    url, stream=True, allow_redirects=False, timeout=(10, 30)
                ) as bare:
                    return _read_media(bare)
            return _read_media(response)
    raise SafetyError("Too many media redirects; no file was written.")


def _read_media(response):
    response.raise_for_status()
    if response.status_code != 200:
        raise SafetyError("Google media did not return a complete file.")
    chunks = []
    size = 0
    for chunk in response.iter_content(64 * 1024):
        size += len(chunk)
        if size > 32 * 1024 * 1024:
            raise SafetyError(
                "Media exceeds the 32 MiB download limit; no file was written."
            )
        chunks.append(chunk)
    return b"".join(chunks), response.headers.get("Content-Type")
