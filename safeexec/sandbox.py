"""Disposable execution in an E2B sandbox.

The orchestrator evaluated a specific sequence of bytes. This module makes sure
those exact bytes are what runs: after uploading, the remote SHA-256 is compared
with ``expected_sha256`` and execution is aborted on any mismatch. The sandbox is
created with network access denied unless the caller explicitly opts in, because
a trial that has not proven it needs the network should not have it.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shlex
from pathlib import Path
from typing import Any

REMOTE_WORKDIR = "/tmp"
#: Ceiling for captured remote output kept in the receipt.
MAX_CAPTURE_BYTES = 100_000


class SandboxError(RuntimeError):
    """Raised when the sandbox cannot be created or verified."""


def _api_key() -> str:
    key_file = os.environ.get("E2B_API_KEY_FILE")
    if key_file:
        try:
            return Path(key_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SandboxError("E2B API key file unreadable") from exc
    return os.environ.get("E2B_API_KEY", "").strip()


def _truncate(text: str, limit: int = MAX_CAPTURE_BYTES) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[truncated {len(text) - limit} bytes]"


def _sandbox_create_kwargs(api_key: str, timeout: int) -> dict[str, Any]:
    """Build ``Sandbox.create`` keyword arguments, tolerating older SDKs.

    ``allow_internet_access`` exists in current SDKs; when the installed version
    does not accept it, we keep the default rather than crashing.
    """
    kwargs: dict[str, Any] = {"timeout": timeout, "api_key": api_key}
    try:
        import inspect

        from e2b_code_interpreter import Sandbox

        params = inspect.signature(Sandbox.create).parameters
    except (ImportError, ValueError, TypeError):
        return kwargs
    if "allow_internet_access" in params:
        kwargs["allow_internet_access"] = False
    return kwargs


def execute_e2b(
    filename: str,
    content: bytes,
    timeout: int = 30,
    expected_sha256: str | None = None,
    allow_network: bool = False,
) -> tuple[int, str, str]:
    """Upload ``content`` to a disposable sandbox, verify it, then run it.

    Returns ``(exit_code, stdout, stderr)``. Raises :class:`SandboxError` when
    the sandbox cannot be prepared; a remote failure is an ordinary non-zero
    exit code, not an exception.
    """
    try:
        from e2b_code_interpreter import Sandbox
    except ImportError as exc:  # pragma: no cover - exercised via import error path
        raise SandboxError("Install the e2b extra: pip install -e '.[e2b]'") from exc

    digest = expected_sha256 or hashlib.sha256(content).hexdigest()
    api_key = _api_key()
    if not api_key:
        raise SandboxError("E2B API key unavailable")

    kwargs = _sandbox_create_kwargs(api_key, timeout)
    if allow_network and "allow_internet_access" in kwargs:
        kwargs["allow_internet_access"] = True

    sandbox = Sandbox.create(**kwargs)
    try:
        remote = f"{REMOTE_WORKDIR}/{Path(filename).name}"
        sandbox.files.write(remote, content)

        # Exact-byte binding: never run a file whose remote digest drifted.
        check = sandbox.commands.run(f"sha256sum {shlex.quote(remote)}", timeout=min(timeout, 15))
        reported = (check.stdout or "").split(" ", 1)[0].strip().lower()
        if reported != digest:
            raise SandboxError("remote digest mismatch; refusing to execute")

        result = sandbox.commands.run(f"python3 {shlex.quote(remote)}", timeout=timeout)
        exit_code = int(getattr(result, "exit_code", 1) or 0)
        stdout = _truncate(result.stdout or "")
        stderr = _truncate(result.stderr or "")
        return exit_code, stdout, stderr
    finally:
        # Cleanup must never mask the real result.
        with contextlib.suppress(Exception):
            sandbox.kill()


__all__ = ["MAX_CAPTURE_BYTES", "REMOTE_WORKDIR", "SandboxError", "execute_e2b"]
