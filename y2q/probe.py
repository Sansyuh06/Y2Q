import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional

from y2q.validate import Target

CONNECT_TIMEOUT_SEC = 5.0
TOTAL_TIMEOUT_SEC = 10.0


@dataclass(frozen=True)
class ProbeExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    is_timeout: bool = False
    timeout_reason: Optional[str] = None


def find_openssl_binary() -> str:
    env_bin = os.environ.get("OPENSSL_BIN")
    if env_bin and os.path.isfile(env_bin):
        return env_bin

    which_bin = shutil.which("openssl")
    if which_bin:
        return which_bin

    if sys.platform == "win32":
        candidate = r"C:\Program Files\Git\usr\bin\openssl.exe"
        if os.path.isfile(candidate):
            return candidate

    raise FileNotFoundError("openssl binary not found in PATH or standard locations")


def get_openssl_version(openssl_bin: Optional[str] = None) -> str:
    bin_path = openssl_bin or find_openssl_binary()
    try:
        proc = subprocess.run(
            [bin_path, "version"],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=5.0,
        )
        out = proc.stdout.strip()
        if out:
            # e.g., "OpenSSL 3.5.7 9 Jun 2026 ..." -> "OpenSSL 3.5.7"
            parts = out.split()
            if len(parts) >= 2:
                return f"{parts[0]} {parts[1]}"
            return out
        return "OpenSSL (unknown version)"
    except Exception as err:
        return f"OpenSSL error: {err}"


def build_s_client_args(
    openssl_bin: str,
    target: Target,
    test_type: str,
) -> List[str]:
    """Construct argument list for openssl s_client. Never build a command string."""
    args = [
        openssl_bin,
        "s_client",
        "-connect",
        target.connect_target,
    ]

    # Omit -servername when the target is an IP literal. SNI must not carry an IP.
    if target.sni_hostname is not None:
        args.extend(["-servername", target.sni_hostname])

    args.append("-tls1_3")

    if test_type == "forced_hybrid":
        args.extend(["-groups", "X25519MLKEM768"])
    elif test_type == "forced_classical":
        args.extend(["-groups", "X25519"])
    elif test_type == "default":
        pass
    else:
        raise ValueError(f"Unknown test_type: {test_type}")

    return args


def execute_probe(
    openssl_bin: str,
    target: Target,
    test_type: str,
    connect_timeout: float = CONNECT_TIMEOUT_SEC,
    total_timeout: float = TOTAL_TIMEOUT_SEC,
) -> ProbeExecutionResult:
    """Execute openssl s_client with strict timeouts and process reaping."""
    args = build_s_client_args(openssl_bin, target, test_type)

    start_time = time.monotonic()
    try:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
    except Exception as err:
        return ProbeExecutionResult(
            stdout="",
            stderr=str(err),
            exit_code=1,
            is_timeout=False,
            timeout_reason=None,
        )

    # Monitor connect deadline (5s) and total deadline (10s)
    connected_detected = False
    stdout_chunks: List[str] = []
    stderr_chunks: List[str] = []

    try:
        # Use communicate with total timeout deadline
        # For connect timeout detection: on fast networks s_client completes within 5s.
        # If it takes > 5s and has not reached CONNECTED, we check.
        try:
            # We first wait up to connect_timeout for initial completion or connection
            stdout_text, stderr_text = proc.communicate(timeout=connect_timeout)
            return ProbeExecutionResult(
                stdout=stdout_text or "",
                stderr=stderr_text or "",
                exit_code=proc.returncode if proc.returncode is not None else 0,
                is_timeout=False,
            )
        except subprocess.TimeoutExpired:
            # Process is still running after connect_timeout.
            # Check if it has connected by inspecting partial output if possible,
            # or wait remaining time up to total_timeout.
            remaining = total_timeout - connect_timeout
            if remaining <= 0:
                proc.kill()
                proc.wait()
                return ProbeExecutionResult(
                    stdout="",
                    stderr="Connection timed out",
                    exit_code=1,
                    is_timeout=True,
                    timeout_reason="timeout",
                )

            try:
                stdout_text, stderr_text = proc.communicate(timeout=remaining)
                # If "CONNECTED" is not in stdout, connect timed out
                if "CONNECTED" not in (stdout_text or ""):
                    return ProbeExecutionResult(
                        stdout=stdout_text or "",
                        stderr=stderr_text or "",
                        exit_code=proc.returncode if proc.returncode is not None else 1,
                        is_timeout=True,
                        timeout_reason="timeout",
                    )
                return ProbeExecutionResult(
                    stdout=stdout_text or "",
                    stderr=stderr_text or "",
                    exit_code=proc.returncode if proc.returncode is not None else 0,
                    is_timeout=False,
                )
            except subprocess.TimeoutExpired:
                # Exceeded total_timeout: kill and reap child
                proc.kill()
                proc.wait()
                return ProbeExecutionResult(
                    stdout="",
                    stderr="Total execution deadline exceeded",
                    exit_code=1,
                    is_timeout=True,
                    timeout_reason="timeout",
                )
    except Exception as err:
        try:
            proc.kill()
            proc.wait()
        except Exception:
            pass
        return ProbeExecutionResult(
            stdout="",
            stderr=str(err),
            exit_code=1,
            is_timeout=False,
        )
