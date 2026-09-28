"""S6c/7a, 5 (spec/11 T1, spec/09): XML-RPC-Sonde und SMTP-EHLO als Rohdaten."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner import phase2


# ---- XML-RPC -------------------------------------------------------------

def _mock_curl_out(output: str):
    proc = MagicMock()
    proc.communicate.return_value = (output, "")
    proc.pid = 1
    return patch.object(phase2.subprocess, "Popen", return_value=proc)


def test_xmlrpc_erkannt(tmp_path: Path) -> None:
    (tmp_path / "phase2").mkdir()
    resp = ("<methodResponse><params><param><value><array><data>"
            "<value><string>system.listMethods</string></value>"
            "<value><string>wp.getUsersBlogs</string></value>"
            "</data></array></value></param></params></methodResponse>"
            "\n__VS_CODE__:200")
    with patch.object(phase2, "record_tool_run"), _mock_curl_out(resp):
        r = phase2.run_xmlrpc_probe("dortmund-beach.com", "1.2.3.4", str(tmp_path), "o")
    assert r["xmlrpc_enabled"] is True
    assert r["status"] == 200


def test_xmlrpc_abgeschaltet(tmp_path: Path) -> None:
    (tmp_path / "phase2").mkdir()
    resp = ("<methodResponse><fault><value><struct><member><name>faultCode</name>"
            "<value><int>405</int></value></member></struct></value></fault></methodResponse>"
            "\n__VS_CODE__:405")
    with patch.object(phase2, "record_tool_run"), _mock_curl_out(resp):
        r = phase2.run_xmlrpc_probe("x.example", "1.2.3.4", str(tmp_path), "o")
    assert r["xmlrpc_enabled"] is False
    assert r["fault"] is True


# ---- SMTP EHLO -----------------------------------------------------------

class _FakeSock:
    def __init__(self, ehlo_lines):
        self._banner_sent = False
        self._ehlo = ehlo_lines
        self._recv_stage = 0

    def settimeout(self, *_):
        pass

    def sendall(self, *_):
        pass

    def recv(self, _n):
        if self._recv_stage == 0:
            self._recv_stage = 1
            return b"220 mail.dortmund-beach.com ESMTP\r\n"
        if self._recv_stage == 1:
            self._recv_stage = 2
            return self._ehlo.encode()
        return b""

    def close(self):
        pass


def test_smtp_ehlo_erfasst_auth_vor_starttls(tmp_path: Path) -> None:
    (tmp_path / "phase2").mkdir()
    ehlo = ("250-mail.dortmund-beach.com\r\n"
            "250-AUTH PLAIN LOGIN\r\n"
            "250-VRFY\r\n"
            "250 STARTTLS\r\n")
    with patch("socket.create_connection", return_value=_FakeSock(ehlo)), \
         patch.object(phase2, "record_tool_run"):
        r = phase2.run_smtp_ehlo("mail.dortmund-beach.com", "1.2.3.4", 587,
                                 str(tmp_path), "o")
    assert r["starttls"] is True
    assert r["vrfy"] is True
    assert r["auth_before_starttls"] is True
    assert any("PLAIN" in a for a in r["auth_mechanisms"])
