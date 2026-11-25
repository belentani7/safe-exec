"""Sandbox contract tests using a fake E2B SDK.

These assert the property that matters most: the bytes executed in the sandbox
are exactly the bytes that were evaluated, and drift aborts execution.
"""

from __future__ import annotations

import hashlib
import types

import pytest
from safeexec import sandbox


class FakeResult:
    def __init__(self, exit_code: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class FakeCommands:
    def __init__(self, owner: FakeSandbox) -> None:
        self.owner = owner

    def run(self, command: str, timeout: int | None = None) -> FakeResult:
        self.owner.commands_run.append(command)
        if command.startswith("sha256sum"):
            return FakeResult(stdout=f"{self.owner.remote_digest}  /tmp/sample.py\n")
        return FakeResult(stdout="ran\n")


class FakeFiles:
    def __init__(self, owner: FakeSandbox) -> None:
        self.owner = owner

    def write(self, path: str, content: bytes) -> None:
        self.owner.written.append((path, content))
        self.owner.remote_digest = hashlib.sha256(content).hexdigest()


class FakeSandbox:
    created: list[FakeSandbox] = []
    digest_override: str | None = None

    def __init__(self) -> None:
        self.written: list[tuple[str, bytes]] = []
        self.commands_run: list[str] = []
        self.killed = False
        self.remote_digest = ""
        self.files = FakeFiles(self)
        self.commands = FakeCommands(self)
        FakeSandbox.created.append(self)

    @classmethod
    def create(
        cls,
        template=None,
        timeout=None,
        metadata=None,
        envs=None,
        secure=None,
        allow_internet_access=None,
        **_kwargs,
    ):
        # Mirrors the real E2B signature so capability probing behaves the same.
        kwargs = {
            "timeout": timeout,
            "allow_internet_access": allow_internet_access,
        }
        instance = cls()
        instance.create_kwargs = kwargs
        if cls.digest_override is not None:
            instance.remote_digest = cls.digest_override
        return instance

    def kill(self) -> None:
        self.killed = True


def _corrupted_init(self) -> None:
    self.written = []
    self.commands_run = []
    self.killed = False
    self.remote_digest = "deadbeef" * 8
    self.create_kwargs = {}
    self.files = FakeFiles(self)
    self.commands = FakeCommands(self)


@pytest.fixture
def fake_sdk(monkeypatch, tmp_path):
    FakeSandbox.created.clear()
    FakeSandbox.digest_override = None
    module = types.SimpleNamespace(Sandbox=FakeSandbox)
    monkeypatch.setitem(__import__("sys").modules, "e2b_code_interpreter", module)
    key = tmp_path / "e2b.key"
    key.write_text("test-key", encoding="utf-8")
    monkeypatch.setenv("E2B_API_KEY_FILE", str(key))
    monkeypatch.delenv("E2B_API_KEY", raising=False)
    return FakeSandbox


def test_uploaded_bytes_match_the_evaluated_bytes(fake_sdk) -> None:
    content = b"print('exact')\n"
    exit_code, stdout, _ = sandbox.execute_e2b("sample.py", content, expected_sha256=hashlib.sha256(content).hexdigest())
    assert exit_code == 0
    assert stdout == "ran\n"
    written_path, written = fake_sdk.created[0].written[0]
    assert written == content
    assert written_path == "/tmp/sample.py"
    assert fake_sdk.created[0].killed is True


def test_remote_digest_drift_aborts_before_execution(fake_sdk, monkeypatch) -> None:
    # Simulate a corrupted upload: the remote digest no longer matches.
    monkeypatch.setattr(FakeFiles, "write", lambda self, path, content: None)
    monkeypatch.setattr(FakeSandbox, "__init__", _corrupted_init)
    created: list = []
    original_create = FakeSandbox.create.__func__

    def tracking_create(cls, **kwargs):
        instance = original_create(cls, **kwargs)
        created.append(instance)
        return instance

    monkeypatch.setattr(FakeSandbox, "create", classmethod(tracking_create))
    with pytest.raises(sandbox.SandboxError):
        sandbox.execute_e2b("sample.py", b"print(1)\n")
    commands = created[0].commands_run
    assert any(cmd.startswith("sha256sum") for cmd in commands)
    assert not any(cmd.startswith("python3") for cmd in commands)
    assert created[0].killed is True


def test_missing_api_key_raises_before_creating_sandbox(fake_sdk, monkeypatch) -> None:
    monkeypatch.delenv("E2B_API_KEY_FILE", raising=False)
    monkeypatch.delenv("E2B_API_KEY", raising=False)
    with pytest.raises(sandbox.SandboxError):
        sandbox.execute_e2b("sample.py", b"print(1)\n")
    assert fake_sdk.created == []


def test_sandbox_is_killed_even_when_execution_raises(fake_sdk, monkeypatch) -> None:
    def boom(self, command, timeout=None):
        raise RuntimeError("transport exploded")

    monkeypatch.setattr(FakeCommands, "run", boom)
    with pytest.raises(RuntimeError):
        sandbox.execute_e2b("sample.py", b"print(1)\n")
    assert fake_sdk.created[0].killed is True


def test_output_is_truncated_to_budget(fake_sdk, monkeypatch) -> None:
    def big(self, command, timeout=None):
        if command.startswith("sha256sum"):
            return FakeResult(stdout=f"{self.owner.remote_digest}  x\n")
        return FakeResult(stdout="x" * (sandbox.MAX_CAPTURE_BYTES + 10))

    monkeypatch.setattr(FakeCommands, "run", big)
    _, stdout, _ = sandbox.execute_e2b("sample.py", b"print(1)\n")
    assert "truncated" in stdout
    assert len(stdout) < sandbox.MAX_CAPTURE_BYTES + 200


def test_network_denied_by_default(fake_sdk) -> None:
    sandbox.execute_e2b("sample.py", b"print(1)\n")
    assert fake_sdk.created[0].create_kwargs.get("allow_internet_access") is False
