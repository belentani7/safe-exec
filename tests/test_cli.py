"""CLI behaviour: human output, JSON schema, limits, and exit codes."""

from __future__ import annotations

import json

import pytest
from safeexec.cli import main, run_command


def invoke(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code


def test_safe_file_is_allowed_and_names_the_hash(tmp_path, capsys) -> None:
    target = tmp_path / "ok.py"
    target.write_text("print('safe')\n", encoding="utf-8")
    assert invoke(["scan", str(target)]) == 0
    out = capsys.readouterr().out
    assert "allowed" in out
    assert "sha256=" in out


def test_quiet_suppresses_success_output(tmp_path, capsys) -> None:
    target = tmp_path / "ok.py"
    target.write_text("print('safe')\n", encoding="utf-8")
    assert invoke(["scan", str(target), "--quiet"]) == 0
    assert capsys.readouterr().out == ""


def test_dangerous_file_is_denied_with_explanation(tmp_path, capsys) -> None:
    target = tmp_path / "bad.py"
    target.write_text("import os\nos.system('id')\n", encoding="utf-8")
    assert invoke(["scan", str(target)]) == 1
    captured = capsys.readouterr()
    assert "denied" in captured.out
    assert "blocked-call" in captured.out
    # The honesty note belongs on stderr so machine consumers are unaffected.
    assert "not a guarantee of safety" in captured.err


def test_json_report_is_valid_and_stable(tmp_path, capsys) -> None:
    target = tmp_path / "bad.py"
    target.write_text("import os\nos.system('id')\n", encoding="utf-8")
    assert invoke(["scan", str(target), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == 1
    assert report["allowed"] is False
    assert set(report) == {"schema_version", "file_sha256", "allowed", "findings"}


def test_hash_matches_hashlib(tmp_path, capsys) -> None:
    import hashlib

    target = tmp_path / "x.py"
    content = b"# big\n" * 5000
    target.write_bytes(content)
    assert invoke(["hash", str(target)]) == 0
    assert capsys.readouterr().out.strip() == hashlib.sha256(content).hexdigest()


def test_oversized_file_is_denied(tmp_path, capsys) -> None:
    target = tmp_path / "big.py"
    target.write_bytes(b"x = 1\n" * 200_000)
    assert invoke(["scan", str(target), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["findings"][0]["rule"] == "oversized-source"


def test_bom_is_not_a_syntax_error(tmp_path, capsys) -> None:
    target = tmp_path / "bom.py"
    target.write_bytes("\ufeffprint('hola')\n".encode())
    assert invoke(["scan", str(target), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["allowed"] is True


def test_custom_rules_path_is_honoured(tmp_path, capsys) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text("blocked_calls: [print]\n", encoding="utf-8")
    target = tmp_path / "x.py"
    target.write_text("print('x')\n", encoding="utf-8")
    assert invoke(["scan", str(target), "--rules", str(rules), "--json"]) == 1


def test_missing_file_is_a_usage_error(tmp_path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(tmp_path / "absent.py")])
    assert exc.value.code == 2


def test_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "safe-exec" in capsys.readouterr().out


def test_run_command_returns_status_without_exiting(tmp_path) -> None:
    target = tmp_path / "ok.py"
    target.write_text("print(1)\n", encoding="utf-8")
    assert run_command(["scan", str(target), "--quiet"]) == 0
