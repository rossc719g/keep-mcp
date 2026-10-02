"""Interactive credential setup; secrets never appear in command arguments."""

import argparse
import getpass
import logging
import secrets
import sys

import gkeepapi
import gpsoauth

from .credentials import account_email, master_token, store_credentials, validate_email
from .keep_api import BoundedKeepAPI, BoundedSession
from .storage import SafetyError


def check_credentials(email, token):
    keep = gkeepapi.Keep()
    keep._keep_api = BoundedKeepAPI()
    keep._media_api._session = BoundedSession()
    try:
        keep.authenticate(email, token)
    except Exception:
        raise SafetyError(
            "Google did not accept this Keep login. Complete Google's normal verification "
            "or obtain a fresh token. Do not disable MFA, device management, or macOS protections. "
            "No credential was written."
        ) from None


def main():
    logging.disable(logging.CRITICAL)
    parser = argparse.ArgumentParser(
        description="Store Google Keep credentials directly in macOS Keychain."
    )
    parser.add_argument("mode", choices=("token", "exchange", "check"))
    parser.add_argument("--email", help="Google account email, never a token")
    args = parser.parse_args()
    try:
        if args.mode == "check":
            email = account_email()
            check_credentials(email, master_token(email))
            print("Google Keep authentication and read synchronization succeeded.")
            return
        if not sys.stdin.isatty():
            raise SafetyError(
                "Credential setup requires an interactive terminal with hidden input. Never put a token in command arguments or environment variables."
            )
        email = validate_email(args.email or input("Google account email: ").strip())
        if args.mode == "exchange":
            print(
                "Complete Google's browser-assisted sign-in yourself, then paste its oauth_token into the hidden prompt below."
            )
            print(
                "Instructions: https://github.com/simon-weber/gpsoauth#alternative-flow"
            )
            oauth = getpass.getpass("Browser oauth_token (hidden): ")
            try:
                response = gpsoauth.exchange_token(email, oauth, secrets.token_hex(8))
                token = response.get("Token")
            except Exception:
                raise SafetyError(
                    "Google token exchange failed. No credential was saved. Follow Google's normal sign-in verification and try again."
                ) from None
            finally:
                del oauth
            if not token:
                raise SafetyError(
                    "Google did not issue a master token. No credential was saved; do not weaken Google security settings."
                )
        else:
            token = getpass.getpass("Google master token (hidden): ")
        try:
            check_credentials(email, token)
            store_credentials(email, token)
        finally:
            del token
        print(
            "Verified and stored in login Keychain. Configuration contains only the account email. The Keep MCP is ready."
        )
    except SafetyError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    except (KeyboardInterrupt, EOFError):
        print("Setup cancelled.", file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        print(
            "Setup could not finish. Check local permissions and Keychain access. No secret details are printed.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
