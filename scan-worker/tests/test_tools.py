"""Tests for the tool-runner subprocess wrapper."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest


def _make_mock_popen(returncode=0, stdout="output data", stderr=""):
    """Create a mock Popen instance that supports communicate()."""
    mock_proc = MagicMock()
    mock_proc.communicate.return_value = (stdout, stderr)
    mock_proc.returncode = returncode
    mock_proc.pid = 12345
    return mock_proc


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.Popen")
def test_run_tool_success(mock_popen: MagicMock, mock_save: MagicMock) -> None:
    """run_tool returns (exit_code, duration_ms) on successful subprocess."""
    from scanner.tools import run_tool

    mock_popen.return_value = _make_mock_popen(returncode=0, stdout="output data")

    exit_code, duration_ms = run_tool(
        cmd=["echo", "hello"],
        timeout=30,
        order_id="scan-1",
        tool_name="echo",
    )

    assert exit_code == 0
    assert isinstance(duration_ms, int)
    assert duration_ms >= 0
    # PR-VPN (2026-05-03): run_tool injiziert ggf. HTTPS_PROXY-ENV. Wenn
    # VPN nicht aktiv ist, wird env=None uebergeben (subprocess erbt das
    # Process-ENV unmodifiziert).
    mock_popen.assert_called_once_with(
        ["echo", "hello"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env=None,
    )


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.Popen")
def test_run_tool_timeout_returns_minus1(mock_popen: MagicMock, mock_save: MagicMock) -> None:
    """run_tool returns (-1, duration_ms) when subprocess times out."""
    from scanner.tools import run_tool

    mock_proc = _make_mock_popen()
    mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=10)
    mock_popen.return_value = mock_proc

    with patch("scanner.tools._kill_process_group"):
        exit_code, duration_ms = run_tool(
            cmd=["slow-tool"],
            timeout=10,
            order_id="scan-2",
            tool_name="slow",
        )

    assert exit_code == -1
    assert isinstance(duration_ms, int)


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.Popen")
def test_run_tool_exception_returns_minus2(mock_popen: MagicMock, mock_save: MagicMock) -> None:
    """run_tool returns (-2, duration_ms) on general exception."""
    from scanner.tools import run_tool

    mock_popen.side_effect = OSError("No such file or directory")

    exit_code, duration_ms = run_tool(
        cmd=["nonexistent-binary"],
        timeout=30,
        order_id="scan-3",
        tool_name="missing",
    )

    assert exit_code == -2
    assert isinstance(duration_ms, int)


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.Popen")
def test_save_result_called_when_order_id_provided(mock_popen: MagicMock, mock_save: MagicMock) -> None:
    """_save_result is called when order_id is not None."""
    from scanner.tools import run_tool

    mock_popen.return_value = _make_mock_popen(returncode=0, stdout="ok")

    run_tool(
        cmd=["tool"],
        timeout=30,
        order_id="scan-4",
        host_ip="10.0.0.1",
        phase=1,
        tool_name="testtool",
    )

    mock_save.assert_called_once()
    call_kwargs = mock_save.call_args[1]
    assert call_kwargs["order_id"] == "scan-4"
    assert call_kwargs["host_ip"] == "10.0.0.1"
    assert call_kwargs["phase"] == 1
    assert call_kwargs["tool_name"] == "testtool"
    assert call_kwargs["exit_code"] == 0


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.Popen")
def test_save_result_not_called_when_order_id_is_none(mock_popen: MagicMock, mock_save: MagicMock) -> None:
    """_save_result is NOT called when order_id is None."""
    from scanner.tools import run_tool

    mock_popen.return_value = _make_mock_popen(returncode=0, stdout="")

    run_tool(
        cmd=["tool"],
        timeout=30,
        order_id=None,
        tool_name="testtool",
    )

    mock_save.assert_not_called()


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.Popen")
def test_save_result_called_on_timeout_with_order_id(mock_popen: MagicMock, mock_save: MagicMock) -> None:
    """_save_result is called with exit_code=-1 when subprocess times out."""
    from scanner.tools import run_tool

    mock_proc = _make_mock_popen()
    mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=5)
    mock_popen.return_value = mock_proc

    with patch("scanner.tools._kill_process_group"):
        run_tool(
            cmd=["slow"],
            timeout=5,
            order_id="scan-5",
            tool_name="slow",
        )

    mock_save.assert_called_once()
    assert mock_save.call_args[1]["exit_code"] == -1


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.Popen")
def test_save_result_called_on_exception_with_order_id(mock_popen: MagicMock, mock_save: MagicMock) -> None:
    """_save_result is called with exit_code=-2 on general exception."""
    from scanner.tools import run_tool

    mock_popen.side_effect = RuntimeError("boom")

    run_tool(
        cmd=["broken"],
        timeout=30,
        order_id="scan-6",
        tool_name="broken",
    )

    mock_save.assert_called_once()
    assert mock_save.call_args[1]["exit_code"] == -2
