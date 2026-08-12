from __future__ import annotations

import shlex
import os
from pathlib import Path


def execute_e2b(filename: str, content: bytes, timeout: int = 30) -> tuple[int, str, str]:
    try:
        from e2b_code_interpreter import Sandbox
    except ImportError as exc:
        raise RuntimeError("Install the e2b extra: pip install -e '.[e2b]'") from exc
    key_file = os.environ.get("E2B_API_KEY_FILE")
    api_key = Path(key_file).read_text().strip() if key_file else os.environ.get("E2B_API_KEY")
    if not api_key:
        raise RuntimeError("E2B API key unavailable")
    sandbox = Sandbox.create(timeout=timeout, api_key=api_key)
    try:
        remote = f"/tmp/{Path(filename).name}"
        sandbox.files.write(remote, content)
        result = sandbox.commands.run(f"python3 {shlex.quote(remote)}", timeout=timeout)
        return int(getattr(result, "exit_code", 1)), result.stdout, result.stderr
    finally:
        sandbox.kill()
