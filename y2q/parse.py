import re
from dataclasses import dataclass, field
from typing import List, Optional

RE_NEGOTIATED_GROUP = re.compile(r"^Negotiated TLS1\.3 group:\s*(.+)$", re.MULTILINE)
RE_TEMP_KEY = re.compile(
    r"^(?:Server|Peer)\s+Temp\s+Key:\s*([^,\r\n]+)(?:,\s*\d+\s*bits)?",
    re.MULTILINE,
)
RE_CIPHER = re.compile(r"New,\s*[^,]+,\s*Cipher\s+is\s+(\S+)", re.MULTILINE)
RE_PROTOCOL = re.compile(r"^Protocol\s*:\s*(\S+)", re.MULTILINE)
RE_ALERT_NUM = re.compile(r"SSL\s+alert\s+number\s+(\d+)", re.IGNORECASE)
RE_ALERT_DESC = re.compile(r"alert\s+([a-z_ ]+)", re.IGNORECASE)
RE_OPENSSL_ERROR = re.compile(
    r"(?:error:[0-9A-Fa-f]+:[^:\n]+:([^:\n]+)|([^\n]+:\s*errno=\d+))"
)


@dataclass(frozen=True)
class ParsedOutput:
    group: Optional[str]
    tls_version: Optional[str]
    cipher: Optional[str]
    alert_number: Optional[int]
    alert_description: Optional[str]
    error_message: Optional[str]
    raw_errors: List[str] = field(default_factory=list)


def parse_openssl_output(stdout: str, stderr: str = "") -> ParsedOutput:
    combined = f"{stdout}\n{stderr}"

    # 1. Parse group in strict order of priority
    group: Optional[str] = None
    m_group = RE_NEGOTIATED_GROUP.search(combined)
    if m_group:
        val = m_group.group(1).strip()
        if val and val != "<NULL>":
            group = val
    if group is None:
        m_temp = RE_TEMP_KEY.search(combined)
        if m_temp:
            val = m_temp.group(1).strip()
            if val and val != "<NULL>":
                group = val

    # 2. Parse cipher (never infer group from cipher)
    cipher: Optional[str] = None
    m_cipher = RE_CIPHER.search(combined)
    if m_cipher:
        c_val = m_cipher.group(1).strip()
        if c_val and c_val != "(NONE)":
            cipher = c_val

    # 3. Parse protocol / TLS version (only if handshake established a cipher or group)
    tls_version: Optional[str] = None
    if cipher is not None or group is not None:
        m_proto = RE_PROTOCOL.search(combined)
        if m_proto:
            p_val = m_proto.group(1).strip()
            if p_val and p_val != "(NONE)":
                tls_version = p_val
        if tls_version is None:
            m_new_proto = re.search(r"New,\s*(TLSv[0-9.]+),", combined)
            if m_new_proto:
                tls_version = m_new_proto.group(1).strip()

    # 4. Parse alert details
    alert_number: Optional[int] = None
    m_alert_num = RE_ALERT_NUM.search(combined)
    if m_alert_num:
        try:
            alert_number = int(m_alert_num.group(1))
        except ValueError:
            pass

    alert_description: Optional[str] = None
    m_alert_desc = RE_ALERT_DESC.search(combined)
    if m_alert_desc:
        alert_description = m_alert_desc.group(1).strip()

    # 5. Parse OpenSSL errors
    raw_errors: List[str] = []
    for line in stderr.splitlines():
        line_s = line.strip()
        if "error:" in line_s or "errno=" in line_s or "alert" in line_s.lower():
            raw_errors.append(line_s)

    error_message: Optional[str] = None
    if "no suitable key share" in combined.lower():
        error_message = "no suitable key share"
    elif "connection refused" in combined.lower() or "errno=111" in combined:
        error_message = "connection refused"
    elif (
        "name or service not known" in combined.lower()
        or "getaddrinfo failed" in combined.lower()
        or "host not found" in combined.lower()
    ):
        error_message = "dns resolution failed"
    elif alert_description:
        error_message = f"tls alert: {alert_description}"
    elif raw_errors:
        error_message = raw_errors[0]

    return ParsedOutput(
        group=group,
        tls_version=tls_version,
        cipher=cipher,
        alert_number=alert_number,
        alert_description=alert_description,
        error_message=error_message,
        raw_errors=raw_errors,
    )
