import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class Credentials:
    username: str
    password: str


def generate_credentials() -> Credentials:
    return Credentials(
        username=secrets.token_urlsafe(8),
        password=secrets.token_urlsafe(16),
    )


def parse_auth_header(headers: Dict[str, str]) -> Optional[Credentials]:
    auth = headers.get("proxy-authorization", "")
    if not auth:
        return None
    if not auth.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    username, _, password = decoded.partition(":")
    return Credentials(username=username, password=password)


def _constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class AuthManager:

    def __init__(self, config_username: Optional[str] = None,
                 config_password: Optional[str] = None,
                 no_auth: bool = False):
        self.no_auth = no_auth
        if not no_auth and config_username is not None and config_password is not None:
            self.credentials = Credentials(config_username, config_password)
            self._generated = False
        elif not no_auth:
            self.credentials = generate_credentials()
            self._generated = True
        else:
            self.credentials = Credentials("", "")
            self._generated = False

    def authenticate(self, headers: Dict[str, str]) -> bool:
        if self.no_auth:
            return True
        provided = parse_auth_header(headers)
        if provided is None:
            return False
        base_user = provided.username.split("-session-")[0] if "-session-" in provided.username else provided.username
        return (_constant_time_compare(base_user, self.credentials.username) and
                _constant_time_compare(provided.password, self.credentials.password))

    @staticmethod
    def extract_session_id(headers: Dict[str, str]) -> Optional[str]:
        sid = headers.get("x-session-id", "")
        if sid.strip():
            return sid.strip()
        provided = parse_auth_header(headers)
        if provided and "-session-" in provided.username:
            parts = provided.username.split("-session-", 1)
            if len(parts) == 2:
                sid_part = parts[1]
                if "-time-" in sid_part:
                    sid_part = sid_part.split("-time-")[0]
                return sid_part.strip() if sid_part.strip() else None
        return None

    def print_credentials(self) -> None:
        if self.no_auth:
            print("Authentication disabled (--no-auth). Proxy is open.")
            return

        encoded = base64.b64encode(
            f"{self.credentials.username}:{self.credentials.password}".encode()
        ).decode()

        print()
        if self._generated:
            print("Generated proxy credentials:")
        else:
            print("Using configured proxy credentials:")
        print(f"  Username: {self.credentials.username}")
        print(f"  Password: {self.credentials.password}")
        print()
        print("Configure your HTTP client with:")
        print(f"  Proxy-Authorization: Basic {encoded}")
        print()
        print("Include an X-Session-Id header for sticky sessions")
        print("(same exit IP for all requests sharing the same session ID).")
        print("Omit the header for rotating IPs (different exit IP per request).")
        print()
