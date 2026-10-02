"""Interactive credential setup; secrets never appear in command arguments."""

import argparse
import getpass
import logging
import secrets
import sys
import warnings

import gkeepapi
import gpsoauth

from .credentials import account_email, master_token, store_credentials, validate_email
from .keep_api import BoundedKeepAPI, BoundedSession
from .storage import SafetyError


def exchange_error(response):
    guidance = {
        "BadAuthentication": (
            "Google rejected the browser credential. Use a fresh oauth_token cookie "
            "from the same Google account as the email entered here. Copy only its Value."
        ),
        "NeedsBrowser": (
            "Google requires browser verification. Complete its normal sign-in and "
            "any account-verification prompts, then obtain a fresh oauth_token."
        ),
        "CaptchaRequired": (
            "Google requires an interactive verification. Complete normal Google "
            "sign-in in your browser before obtaining a fresh oauth_token."
        ),
        "InvalidSecondFactor": (
            "Google did not accept the sign-in verification. Complete its normal "
            "two-step verification in your browser before obtaining a fresh oauth_token."
        ),
        "MissingDroidguard": (
            "This authentication library could not satisfy Google's device-verification "
            "requirements. Stop here; repeated cookie entry may not resolve this."
        ),
        "ServiceDisabled": "Google has disabled access to this service for the account.",
        "AccountDisabled": "Google reports that the account is disabled.",
    }
    code = response.get("Error")
    if not isinstance(code, str) or code not in guidance:
        code = "UnrecognizedResponse"
        detail = "Google returned no master token and no recognized error code."
    else:
        detail = guidance[code]
    # Only fixed, allowlisted messages may leave Google's credential-bearing response.
    return SafetyError(
        f"Google token exchange failed ({code}). {detail} "
        "No credential was saved. Do not weaken Google security settings."
    )


def read_secret(prompt):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise SafetyError(
                "Hidden input is unavailable. Run setup in a local Terminal; credential input must never be echoed."
            ) from None


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
            oauth = read_secret("Browser oauth_token (hidden): ")
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
                raise exchange_error(response)
        else:
            token = read_secret("Google master token (hidden): ")
        try:
            check_credentials(email, token)
            store_credentials(email, token)
        finally:
            del token
        print(
            "Verified and stored in macOS Keychain. Configuration contains only the account email. The Keep MCP is ready."
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
