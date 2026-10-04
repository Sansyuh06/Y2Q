import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

DNS_LABEL_REGEX = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$")
CONTROL_CHARS_REGEX = re.compile(r"[\x00-\x1f\x7f-\x9f]")


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    is_ip: bool
    raw_input: str

    @property
    def sni_hostname(self) -> Optional[str]:
        # Omit SNI when the target is an IP literal. SNI must not carry an IP.
        return None if self.is_ip else self.host

    @property
    def connect_target(self) -> str:
        # Bracket IPv6 literals for connect strings host:port
        if self.is_ip and ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


def validate_target(target_str: str, default_port: int = 443) -> Target:
    if not isinstance(target_str, str):
        raise ValueError("Target must be a string")

    raw_input = target_str
    s = target_str.strip()

    if not s:
        raise ValueError("Target cannot be empty")

    if CONTROL_CHARS_REGEX.search(s) or any(c.isspace() for c in s):
        raise ValueError("Target contains whitespace or control characters")

    # Reject flag-injection attempts early before any other parsing
    if s.startswith("-"):
        raise ValueError("Target host cannot begin with '-'")

    host_part: str
    port_part: Optional[str] = None

    if s.startswith("["):
        # Bracketed IPv6 literal, possibly with :port
        close_idx = s.find("]")
        if close_idx == -1:
            raise ValueError("Malformed bracketed IPv6 literal: missing closing ']'")
        inside_brackets = s[1:close_idx]
        remainder = s[close_idx + 1 :]
        if remainder:
            if not remainder.startswith(":"):
                raise ValueError(f"Malformed target after IPv6 literal: {remainder}")
            port_part = remainder[1:]
        try:
            ipaddress.IPv6Address(inside_brackets)
        except ValueError as err:
            raise ValueError(f"Invalid IPv6 literal: {err}") from err
        host_part = inside_brackets
        is_ip = True
    else:
        # Hostname, IPv4, or host:port
        if ":" in s:
            parts = s.split(":")
            if len(parts) == 2:
                host_part, port_part = parts[0], parts[1]
            else:
                # Unbracketed IPv6 is out of scope and rejected
                raise ValueError("IPv6 literals must be bracketed like [2001:db8::1]")
        else:
            host_part = s

        # Flag injection check on parsed host part as well
        if host_part.startswith("-"):
            raise ValueError("Target host cannot begin with '-'")

        # Check if host_part is IPv4
        try:
            ipaddress.IPv4Address(host_part)
            is_ip = True
        except ValueError:
            # Check if mistakenly unbracketed IPv6
            try:
                ipaddress.IPv6Address(host_part)
                raise ValueError("IPv6 literals must be bracketed like [2001:db8::1]")
            except ValueError:
                pass
            is_ip = False

    # Validate port
    port: int
    if port_part is not None:
        if not port_part.isdigit():
            raise ValueError(f"Port must be an integer: {port_part}")
        port = int(port_part)
    else:
        port = default_port

    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of valid range 1-65535: {port}")

    # Validate DNS hostname if not IP
    if not is_ip:
        validate_hostname(host_part)

    return Target(host=host_part, port=port, is_ip=is_ip, raw_input=raw_input)


def validate_hostname(hostname: str) -> None:
    if not (1 <= len(hostname) <= 253):
        raise ValueError(f"Hostname length must be 1-253 characters (got {len(hostname)})")

    if hostname.startswith("-") or hostname.endswith("-"):
        raise ValueError("Hostname cannot start or end with '-'")

    labels = hostname.split(".")
    for label in labels:
        if not label:
            raise ValueError("Hostname contains empty label")
        if len(label) > 63:
            raise ValueError(f"Hostname label exceeds 63 characters: {label}")
        if not DNS_LABEL_REGEX.match(label):
            raise ValueError(f"Hostname label contains invalid characters: {label}")


def parse_target_lines(
    lines: Iterable[str],
    default_port: int = 443,
    max_targets: int = 10000,
) -> List[Tuple[str, Optional[Target], Optional[str]]]:
    """Parse batch target lines without I/O.
    
    Handles comments (#), blanks, deduplication, and max input limit.
    Returns list of (raw_line, target_or_none, error_message_or_none).
    """
    results: List[Tuple[str, Optional[Target], Optional[str]]] = []
    seen = set()
    count = 0

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line in seen:
            continue
        seen.add(line)

        count += 1
        if count > max_targets:
            raise ValueError(f"Maximum target limit ({max_targets}) exceeded")

        try:
            target = validate_target(line, default_port=default_port)
            results.append((line, target, None))
        except ValueError as err:
            results.append((line, None, str(err)))

    return results
