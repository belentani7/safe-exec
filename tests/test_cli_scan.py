"""End-to-end CLI scan tests: no sandbox, network, or subprocess execution."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

from safeexec.cli import main


def scan(monkeypatch, capsys, file: Path, *flags: str):
    monkeypatch.setattr(sys, "argv", ["safe-exec", "scan", str(file), *flags])
    with pytest.raises(SystemExit) as exc:
        main()
    return exc.value.code, capsys.readouterr().out


def test_json_report_allows_safe_file_and_matches_hash(tmp_path, monkeypatch, capsys):
    file = tmp_path / "safe.py"
    content = b"print('safe')\n"
    file.write_bytes(content)

    status, output = scan(monkeypatch, capsys, file, "--json")
    report = json.loads(output)

    assert status == 0
    assert report == {
        "schema_version": 1,
        "file_sha256": hashlib.sha256(content).hexdigest(),
        "allowed": True,
        "findings": [],
    }


def test_json_report_blocks_call_without_running_it(tmp_path, monkeypatch, capsys):
    file = tmp_path / "blocked.py"
    file.write_text("import os\nos.system('touch /tmp/never-run')\n", encoding="utf-8")

    status, output = scan(monkeypatch, capsys, file, "--json")
    report = json.loads(output)

    assert status == 1
    assert report["allowed"] is False
    assert any(f["rule"] == "blocked-call" and f["detail"] == "os.system"
               for f in report["findings"])


def test_invalid_encoding_is_a_controlled_denial(tmp_path, monkeypatch, capsys):
    file = tmp_path / "invalid.py"
    file.write_bytes(bytes([0xFF, 0xFE]))

    status, output = scan(monkeypatch, capsys, file, "--json")
    report = json.loads(output)

    assert status == 1
    assert report["allowed"] is False
    assert report["findings"][0]["rule"] == "invalid-encoding"
