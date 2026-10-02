"""Use Security.framework through an explicitly selected macOS Keychain backend."""

import json
import os
import sys
from pathlib import Path

from .storage import SafetyError, private_directory, private_open

KEYCHAIN_SERVICE = "local.keep-mcp.google-master-token"


def config_path() -> Path:
    return Path(
        os.environ.get("KEEP_MCP_CONFIG", Path.home() / ".config/keep-mcp/config.json")
    )


def keychain():
    if sys.platform != "darwin":
        raise SafetyError(
            "This personal server requires macOS Keychain. No plaintext fallback is available."
        )
    from keyring.backends.macOS import Keyring

    backend = Keyring()
    # Ignore KEYCHAIN_PATH and dynamic backend selection, including plaintext plugins.
    backend.keychain = None
    return backend


def validate_email(email: str) -> str:
    if (
        not isinstance(email, str)
        or not 3 <= len(email) <= 320
        or "@" not in email
        or any(c.isspace() for c in email)
    ):
        raise SafetyError(
            "Configure a valid Google account email using keep-mcp-setup."
        )
    return email


def account_email() -> str:
    if os.environ.get("GOOGLE_MASTER_TOKEN"):
        raise SafetyError(
            "Remove GOOGLE_MASTER_TOKEN from the environment and MCP config. Use keep-mcp-setup to store it in Keychain."
        )
    try:
        fd = private_open(config_path(), os.O_RDONLY)
        with os.fdopen(fd) as stream:
            config = json.loads(stream.read(4097))
    except FileNotFoundError:
        raise SafetyError(
            "Google Keep is not configured. Run keep-mcp-setup on this Mac; never paste credentials into chat."
        ) from None
    except (OSError, json.JSONDecodeError):
        raise SafetyError(
            "Cannot read the private Keep account configuration. Run keep-mcp-setup locally."
        ) from None
    if not isinstance(config, dict) or set(config) != {"email"}:
        raise SafetyError(
            "Keep configuration may contain only the account email; credentials belong in Keychain."
        )
    return validate_email(config["email"])


def master_token(email: str) -> str:
    try:
        token = keychain().get_password(KEYCHAIN_SERVICE, email)
    except SafetyError:
        raise
    except Exception:
        raise SafetyError(
            "Cannot access the Keep token in macOS Keychain. Unlock it or approve the normal macOS access prompt locally; do not weaken Keychain permissions."
        ) from None
    if not token:
        raise SafetyError(
            "No Google Keep token exists in Keychain for this account. Run keep-mcp-setup locally; never paste the token into chat."
        )
    return token


def store_credentials(email: str, token: str) -> None:
    validate_email(email)
    if not isinstance(token, str) or not token.strip() or "\n" in token:
        raise SafetyError("The credential is empty or invalid.")
    try:
        keychain().set_password(KEYCHAIN_SERVICE, email, token)
    except Exception:
        raise SafetyError(
            "Keychain could not store the credential. Use the normal macOS access prompt and try again."
        ) from None
    path = config_path()
    private_directory(path.parent)
    fd = private_open(path, os.O_CREAT | os.O_WRONLY)
    with os.fdopen(fd, "w") as stream:
        stream.truncate(0)
        json.dump({"email": email}, stream)
        stream.flush()
        os.fsync(stream.fileno())
