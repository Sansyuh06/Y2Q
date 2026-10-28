import os
import shutil
import subprocess
import sys
import threading
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
    duration_ms: int = 0


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
            parts = out.split()
            if len(parts) >= 2:
                return f"{parts[0]} {parts[1]}"
            return out
        return "OpenSSL (unknown version)"
    except Exception as err:
        return f"OpenSSL error: {err}"


def check_native_mlkem_support(openssl_bin: Optional[str] = None) -> bool:
    bin_path = openssl_bin or find_openssl_binary()
    try:
        proc = subprocess.run(
            [bin_path, "list", "-kem-algorithms"],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=5.0,
        )
        return "X25519MLKEM768" in proc.stdout or "MLKEM768" in proc.stdout
    except Exception:
        return False


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
    """Execute openssl s_client with strict timeouts and process reaping.

    Enforces a 5s connect timeout (monitoring stdout/stderr for CONNECTED)
    and a 10s total execution deadline.
    """
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

    stdout_chunks: List[str] = []
    stderr_chunks: List[str] = []
    connected_event = threading.Event()

    def read_stdout():
        try:
            if proc.stdout:
                for line in iter(proc.stdout.readline, ""):
                    stdout_chunks.append(line)
                    if "CONNECTED" in line:
                        connected_event.set()
        finally:
            if proc.stdout:
                proc.stdout.close()

    def read_stderr():
        try:
            if proc.stderr:
                for line in iter(proc.stderr.readline, ""):
                    stderr_chunks.append(line)
                    if "CONNECTED" in line:
                        connected_event.set()
        finally:
            if proc.stderr:
                proc.stderr.close()

    t_out = threading.Thread(target=read_stdout, daemon=True)
    t_err = threading.Thread(target=read_stderr, daemon=True)
    t_out.start()
    t_err.start()

    # 1. Check connect timeout milestone (5s)
    connected = connected_event.wait(timeout=connect_timeout)
    if not connected:
        if proc.poll() is None:
            # Process is still running and has not established TCP connect within 5s
            proc.kill()
            proc.wait()
            t_out.join(timeout=0.5)
            t_err.join(timeout=0.5)
            return ProbeExecutionResult(
                stdout="".join(stdout_chunks),
                stderr="".join(stderr_chunks),
                exit_code=1,
                is_timeout=True,
                timeout_reason="connect timeout",
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

    # 2. Check total execution deadline (10s)
    remaining = total_timeout - (time.monotonic() - start_time)
    if remaining > 0:
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            t_out.join(timeout=0.5)
            t_err.join(timeout=0.5)
            return ProbeExecutionResult(
                stdout="".join(stdout_chunks),
                stderr="".join(stderr_chunks),
                exit_code=1,
                is_timeout=True,
                timeout_reason="total timeout",
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )
    else:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
            t_out.join(timeout=0.5)
            t_err.join(timeout=0.5)
            return ProbeExecutionResult(
                stdout="".join(stdout_chunks),
                stderr="".join(stderr_chunks),
                exit_code=1,
                is_timeout=True,
                timeout_reason="total timeout",
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

    t_out.join(timeout=1.0)
    t_err.join(timeout=1.0)

    return ProbeExecutionResult(
        stdout="".join(stdout_chunks),
        stderr="".join(stderr_chunks),
        exit_code=proc.returncode if proc.returncode is not None else 0,
        is_timeout=False,
        duration_ms=int((time.monotonic() - start_time) * 1000),
    )
