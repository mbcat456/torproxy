import base64
import hmac
import secrets
from dataclasses import dataclass


@dataclass
class Credentials:
    username: str
    password: str


def generate_credentials() -> Credentials:
    return Credentials(
        username=secrets.token_urlsafe(8),
        password=secrets.token_urlsafe(16),
    )


def parse_auth_header(headers: dict[str, str]) -> Credentials | None:
    auth = headers.get("proxy-authorization", "")
    if not auth:
        return None
    if not auth.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(auth[6:].strip()).decode("utf-8", errors="replace")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    username, _, password = decoded.partition(":")
    return Credentials(username=username, password=password)


def _constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class AuthManager:
    def __init__(
        self,
        config_username: str | None = None,
        config_password: str | None = None,
        no_auth: bool = False,
    ):
        self.no_auth = no_auth
        if not no_auth:
            generated = generate_credentials()
            username = (
                config_username if config_username is not None else generated.username
            )
            password = (
                config_password if config_password is not None else generated.password
            )
            self.credentials = Credentials(username, password)
            self._generated = config_username is None or config_password is None
        else:
            self.credentials = Credentials("", "")
            self._generated = False

    def authenticate(self, headers: dict[str, str]) -> bool:
        if self.no_auth:
            return True
        provided = parse_auth_header(headers)
        if provided is None:
            return False
        base_user = (
            provided.username.split("-session-")[0]
            if "-session-" in provided.username
            else provided.username
        )
        return _constant_time_compare(
            base_user, self.credentials.username
        ) and _constant_time_compare(provided.password, self.credentials.password)

    @staticmethod
    def extract_session_id(headers: dict[str, str]) -> str | None:
        sid = headers.get("x-session-id", "")
        if sid.strip():
            sid = sid.strip()
            return sid if len(sid) <= 128 else None
        provided = parse_auth_header(headers)
        if provided and "-session-" in provided.username:
            parts = provided.username.split("-session-", 1)
            if len(parts) == 2:
                sid_part = parts[1]
                if "-time-" in sid_part:
                    sid_part = sid_part.split("-time-")[0]
                sid_part = sid_part.strip()
                return sid_part if 0 < len(sid_part) <= 128 else None
        return None

    @staticmethod
    def extract_session_ttl(headers: dict[str, str]) -> int | None:
        header_ttl = headers.get("x-session-ttl", "").strip()
        if header_ttl:
            try:
                ttl = int(header_ttl)
                return ttl if ttl >= 0 else None
            except ValueError:
                return None

        provided = parse_auth_header(headers)
        if provided and "-session-" in provided.username:
            sid_part = provided.username.split("-session-", 1)[1]
            if "-time-" in sid_part:
                suffix = sid_part.split("-time-", 1)[1]
                if "-" in suffix:
                    suffix = suffix.split("-", 1)[0]
                try:
                    ttl = int(suffix)
                    return ttl if ttl >= 0 else None
                except ValueError:
                    return None
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
