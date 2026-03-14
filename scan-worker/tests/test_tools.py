"""Tests for the tool-runner subprocess wrapper."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.run")
def test_run_tool_success(mock_subprocess: MagicMock, mock_save: MagicMock) -> None:
    """run_tool returns (exit_code, duration_ms) on successful subprocess."""
    from scanner.tools import run_tool

    mock_subprocess.return_value = MagicMock(
        returncode=0,
        stdout="output data",
        stderr="",
    )

    exit_code, duration_ms = run_tool(
        cmd=["echo", "hello"],
        timeout=30,
        order_id="scan-1",
        tool_name="echo",
    )

    assert exit_code == 0
    assert isinstance(duration_ms, int)
    assert duration_ms >= 0
    mock_subprocess.assert_called_once_with(
        ["echo", "hello"],
        capture_output=True,
        text=True,
        timeout=30,
    )


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.run")
def test_run_tool_timeout_returns_minus1(mock_subprocess: MagicMock, mock_save: MagicMock) -> None:
    """run_tool returns (-1, duration_ms) when subprocess times out."""
    from scanner.tools import run_tool

    mock_subprocess.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=10)

    exit_code, duration_ms = run_tool(
        cmd=["slow-tool"],
        timeout=10,
        order_id="scan-2",
        tool_name="slow",
    )

    assert exit_code == -1
    assert isinstance(duration_ms, int)


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.run")
def test_run_tool_exception_returns_minus2(mock_subprocess: MagicMock, mock_save: MagicMock) -> None:
    """run_tool returns (-2, duration_ms) on general exception."""
    from scanner.tools import run_tool

    mock_subprocess.side_effect = OSError("No such file or directory")

    exit_code, duration_ms = run_tool(
        cmd=["nonexistent-binary"],
        timeout=30,
        order_id="scan-3",
        tool_name="missing",
    )

    assert exit_code == -2
    assert isinstance(duration_ms, int)


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.run")
def test_save_result_called_when_order_id_provided(mock_subprocess: MagicMock, mock_save: MagicMock) -> None:
    """_save_result is called when order_id is not None."""
    from scanner.tools import run_tool

    mock_subprocess.return_value = MagicMock(returncode=0, stdout="ok", stderr="")

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
@patch("scanner.tools.subprocess.run")
def test_save_result_not_called_when_order_id_is_none(mock_subprocess: MagicMock, mock_save: MagicMock) -> None:
    """_save_result is NOT called when order_id is None."""
    from scanner.tools import run_tool

    mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")

    run_tool(
        cmd=["tool"],
        timeout=30,
        order_id=None,
        tool_name="testtool",
    )

    mock_save.assert_not_called()


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.run")
def test_save_result_called_on_timeout_with_order_id(mock_subprocess: MagicMock, mock_save: MagicMock) -> None:
    """_save_result is called with exit_code=-1 when subprocess times out."""
    from scanner.tools import run_tool

    mock_subprocess.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=5)

    run_tool(
        cmd=["slow"],
        timeout=5,
        order_id="scan-5",
        tool_name="slow",
    )

    mock_save.assert_called_once()
    assert mock_save.call_args[1]["exit_code"] == -1


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.run")
def test_save_result_called_on_exception_with_order_id(mock_subprocess: MagicMock, mock_save: MagicMock) -> None:
    """_save_result is called with exit_code=-2 on general exception."""
    from scanner.tools import run_tool

    mock_subprocess.side_effect = RuntimeError("boom")

    run_tool(
        cmd=["broken"],
        timeout=30,
        order_id="scan-6",
        tool_name="broken",
    )

    mock_save.assert_called_once()
    assert mock_save.call_args[1]["exit_code"] == -2
