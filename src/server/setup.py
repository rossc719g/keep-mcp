"""Interactive credential setup; secrets never appear in command arguments."""

import argparse
import getpass
import logging
import secrets
import sys
import warnings

import gkeepapi
import gpsoauth
import requests

from .credentials import account_email, master_token, store_credentials, validate_email
from .keep_api import BoundedKeepAPI, BoundedSession
from .storage import SafetyError


def authentication_error(code, stage):
    guidance = {
        "BadAuthentication": (
            "Google rejected the credential at this stage. Use a fresh oauth_token cookie "
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
        "HTTP_400": "Google rejected the request format; check client compatibility.",
        "HTTP_401": "Google rejected the access token for this request.",
        "HTTP_403": "Google refused access to Keep for this request.",
        "HTTP_404": "The requested Google service endpoint was not found.",
        "HTTP_429": "Google rate-limited the request. Stop and wait before trying again.",
        "HTTP_500": "Google reported a server error. Try again later.",
        "HTTP_502": "Google reported a gateway error. Try again later.",
        "HTTP_503": "Google reported that the service is unavailable. Try again later.",
        "HTTP_504": "Google reported a gateway timeout. Try again later.",
        "NetworkTimeout": "The request timed out; this does not establish a rejected login.",
        "NetworkConnectionFailed": "The connection failed; check the Mac's normal network access.",
        "TLSFailure": "The secure connection failed. Keep certificate validation enabled.",
        "ParseException": "The client could not parse Google's Keep data; check client compatibility.",
        "ResyncRequiredException": "Google requested a full Keep resync during the initial read.",
        "UpgradeRecommendedException": "Google requested a newer Keep client.",
        "KeyError": "A required field was missing from the response; check client compatibility.",
        "TypeError": "The client encountered an incompatible value; check client compatibility.",
        "ValueError": "The client could not interpret a response value; check client compatibility.",
        "AttributeError": "The client encountered an incompatible object; check client compatibility.",
    }
    if not isinstance(code, str) or code not in guidance:
        code = "UnrecognizedResponse"
        detail = "The failure has no recognized diagnostic. Raw details remain hidden."
    else:
        detail = guidance[code]
    # Only fixed, allowlisted messages may leave Google's credential-bearing response.
    return SafetyError(
        f"{stage} failed ({code}). {detail} "
        "No credential was saved. Do not weaken Google security settings."
    )


def failure_code(error):
    if isinstance(error, gkeepapi.exception.BrowserLoginRequiredException):
        return "NeedsBrowser"
    if isinstance(error, gkeepapi.exception.LoginException):
        return error.args[0] if error.args else None
    if isinstance(error, requests.HTTPError):
        status = getattr(error.response, "status_code", None)
        return f"HTTP_{status}" if type(status) is int else None
    if isinstance(error, gkeepapi.exception.APIException):
        return f"HTTP_{error.code}" if type(error.code) is int else None
    if isinstance(error, requests.exceptions.SSLError):
        return "TLSFailure"
    if isinstance(error, requests.Timeout):
        return "NetworkTimeout"
    if isinstance(error, requests.ConnectionError):
        return "NetworkConnectionFailed"
    for error_type in (
        gkeepapi.exception.ParseException,
        gkeepapi.exception.ResyncRequiredException,
        gkeepapi.exception.UpgradeRecommendedException,
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
    ):
        if isinstance(error, error_type):
            return error_type.__name__
    return None


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
    stage = "Keep authorization"
    try:
        keep.authenticate(email, token, sync=False)
        stage = "Initial Keep read"
        keep.sync()
    except Exception as error:
        raise authentication_error(failure_code(error), stage) from None


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
            except Exception as error:
                raise authentication_error(
                    failure_code(error), "Google token exchange"
                ) from None
            finally:
                del oauth
            if not token:
                raise authentication_error(
                    response.get("Error"), "Google token exchange"
                )
            print(
                "Token exchange succeeded. Checking Keep authorization and first read."
            )
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
