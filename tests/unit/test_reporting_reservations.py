"""Unit tests for stale report reservation recovery and safety controls."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from gitforensics.errors import OutputWriteError
from gitforensics.reporting import _is_pid_running, write_report_to_file


def test_is_pid_running_self() -> None:
    """Test _is_pid_running returns True for current process PID."""
    assert _is_pid_running(os.getpid()) is True


def test_is_pid_running_invalid_pid() -> None:
    """Test _is_pid_running returns False for non-positive PIDs."""
    assert _is_pid_running(0) is False
    assert _is_pid_running(-1) is False


def test_is_pid_running_dead_pid() -> None:
    """Test _is_pid_running returns False when ProcessLookupError is raised."""
    with patch("os.kill", side_effect=ProcessLookupError):
        assert _is_pid_running(999999) is False


def test_stale_reservation_recovery_when_pid_dead(tmp_path: Path) -> None:
    """Test requirement 1 & 7: stale reservation file left by dead PID is recovered safely."""
    out_file = tmp_path / "report.json"
    lock_file = tmp_path / ".report.json.gitforensics.lock"

    # Create a stale lock file with a dead PID (e.g. 999999)
    stale_meta = {"pid": 999999, "created_at": 1000000.0}
    lock_file.write_text(json.dumps(stale_meta), encoding="utf-8")

    with patch("gitforensics.reporting._is_pid_running", return_value=False):
        write_report_to_file('{"status": "ok"}', str(out_file))

    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == '{"status": "ok"}'
    assert not lock_file.exists()


def test_active_reservation_protection_when_pid_alive(tmp_path: Path) -> None:
    """Test requirement 1: active PID reservation is never deleted and causes OutputWriteError."""
    out_file = tmp_path / "report.json"
    lock_file = tmp_path / ".report.json.gitforensics.lock"

    active_meta = {"pid": 12345, "created_at": 1000000.0}
    lock_file.write_text(json.dumps(active_meta), encoding="utf-8")

    with patch("gitforensics.reporting._is_pid_running", return_value=True):
        with pytest.raises(OutputWriteError, match="reserved by an active process"):
            write_report_to_file('{"status": "ok"}', str(out_file))

    assert not out_file.exists()
    assert lock_file.exists()  # Lock file MUST NOT be deleted


def test_malformed_reservation_treated_as_unsafe(tmp_path: Path) -> None:
    """Test requirement 4: malformed reservation file is treated as unsafe."""
    out_file = tmp_path / "report.json"
    lock_file = tmp_path / ".report.json.gitforensics.lock"

    # Write corrupt JSON
    lock_file.write_text("NOT_VALID_JSON{", encoding="utf-8")

    with pytest.raises(OutputWriteError, match="malformed or unreadable"):
        write_report_to_file('{"status": "ok"}', str(out_file))

    assert not out_file.exists()
    assert lock_file.exists()


def test_symlink_reservation_treated_as_unsafe(tmp_path: Path) -> None:
    """Test requirement 11: symlink reservation file is treated as unsafe and not deleted."""
    out_file = tmp_path / "report.json"
    lock_file = tmp_path / ".report.json.gitforensics.lock"
    target_file = tmp_path / "other_target.txt"
    target_file.write_text("target content", encoding="utf-8")

    try:
        os.symlink(target_file, lock_file)
    except OSError:
        lock_file.write_text("simulated link", encoding="utf-8")
        with patch(
            "gitforensics.reporting.os.path.islink",
            side_effect=lambda path: Path(path) == lock_file,
        ):
            with pytest.raises(OutputWriteError, match="symbolic link"):
                write_report_to_file('{"status": "ok"}', str(out_file))
        assert lock_file.exists()
    else:
        with pytest.raises(OutputWriteError, match="symbolic link"):
            write_report_to_file('{"status": "ok"}', str(out_file))
        assert os.path.islink(lock_file)

    assert not out_file.exists()
