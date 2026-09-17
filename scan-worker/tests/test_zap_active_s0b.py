"""S0b: Namensbildung, Policy-Idempotenz, Scanner-ID-Validierung, Affinitaet.

Hintergrund: zap_active lieferte in 42 Produktionsscans nie ein Ergebnis
(26x does_not_exist, 2x url_not_found, 1x url_not_in_context, 1x
illegal_parameter). Jeder Test hier haelt genau einen der Defekte fest.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from scanner.tools.zap_client import ZapClient, ZapError, safe_name_part


@pytest.fixture
def zap():
    return ZapClient(base_url="http://localhost:8090")


# ---------------------------------------------------------------------------
# Namensbildung
# ---------------------------------------------------------------------------

class TestSafeNamePart:
    """ZAP verbietet / \\ : ; " ' in Policy-Namen (isLegalPolicyName).

    Die alte Bildung ``ip.replace(".", "_")`` liess bei IPv6 die Doppelpunkte
    stehen, ZAP antwortete illegal_parameter.
    """

    def test_ipv4_bleibt_lesbar(self):
        assert safe_name_part("188.40.3.130") == "188_40_3_130"

    def test_ipv6_verliert_die_doppelpunkte(self):
        assert safe_name_part("2a01:238:4231:ea00::1") == "2a01_238_4231_ea00__1"

    def test_verbotene_zeichen_verschwinden(self):
        assert safe_name_part("a/b\\c;d\"e'f") == "a_b_c_d_e_f"

    def test_leerwert(self):
        assert safe_name_part("") == ""


class TestNamensbildungGemeinsam:
    """phase2 und die Pool-Bereinigung muessen denselben Namen bilden.

    Sonst haelt cleanup_stale_contexts einen laufenden Kontext fuer fremd.
    """

    @pytest.mark.parametrize("ip", ["188.40.3.130", "2a01:238:4231:ea00::1"])
    def test_kontextname_ueberlebt_den_lease_value(self, ip):
        """Der Lease-Value ist ``:``-getrennt, IPv6 enthaelt selbst ``:``.

        Ohne Entschaerfung kam in get_all_active_context_names nur das erste
        Hextet an, der Kontext eines laufenden IPv6-Scans galt als verwaist
        und wurde von cleanup_stale_contexts geloescht.
        """
        from scanner.zap_pool import (_build_lease_value, build_context_name,
                                      get_all_active_context_names)

        order_id = "abcdefgh-1234-5678-9012-345678901234"
        erwartet = build_context_name(order_id, ip)
        lease_value = _build_lease_value(order_id, ip, "scan-worker-1")

        fake = MagicMock()
        fake.scan_iter.return_value = [b"zap:lease:zap-1"]
        fake.get.return_value = lease_value.encode()
        assert get_all_active_context_names(fake) == {erwartet}

    def test_policyname_enthaelt_keine_verbotenen_zeichen(self):
        from scanner.zap_pool import build_policy_name

        name = build_policy_name("abcdefgh-1234", "2a01:238:4231:ea00::1")
        for char in "/\\:;\"'":
            assert char not in name


# ---------------------------------------------------------------------------
# Scanner-IDs
# ---------------------------------------------------------------------------

class TestScannerIdResolution:
    """Unbekannte Scanner-IDs duerfen enableScanners nie erreichen.

    ZAP lehnt den Aufruf sonst mit does_not_exist ab, und damit scheitert die
    gesamte Policy-Erzeugung, also auch der Active Scan.
    """

    def test_unbekannte_ids_werden_verworfen(self, zap):
        with patch.object(zap, "get_installed_scanner_ids", return_value={40012, 40018}):
            enabled, dropped = zap.resolve_scanner_ids(["xss", "sqli"])
        assert enabled == {40012, 40018}
        assert 40014 in dropped

    def test_verbotene_scanner_bleiben_draussen(self, zap):
        forbidden = sorted(ZapClient.FORBIDDEN_SCANNERS)[0]
        with patch.dict(ZapClient.CATEGORY_SCANNER_IDS, {"fake": [forbidden, 40012]}):
            with patch.object(zap, "get_installed_scanner_ids",
                              return_value={forbidden, 40012}):
                enabled, dropped = zap.resolve_scanner_ids(["fake"])
        assert forbidden not in enabled
        assert forbidden not in dropped

    def test_view_ausfall_faellt_auf_wunschliste_zurueck(self, zap):
        # fail-open: die Sicht ist nur eine Vorpruefung, ihr Ausfall darf den
        # Scan nicht kippen (Laufzeitabhaengigkeit, kein Image-Inhalt).
        with patch.object(zap, "get_installed_scanner_ids",
                          side_effect=ZapError("view kaputt", endpoint="/x")):
            enabled, dropped = zap.resolve_scanner_ids(["xss"])
        assert enabled == set(ZapClient.CATEGORY_SCANNER_IDS["xss"])
        assert dropped == set()

    def test_leere_kategorie_ergibt_nichts(self, zap):
        enabled, dropped = zap.resolve_scanner_ids(["defaultlogin"])
        assert enabled == set()
        assert dropped == set()

    def test_passive_regeln_stehen_nicht_mehr_im_katalog(self):
        # 10010 und 10054 sind passive Regeln; in einer Active-Scan-Policy
        # existieren sie nicht.
        alle = {i for ids in ZapClient.CATEGORY_SCANNER_IDS.values() for i in ids}
        assert 10010 not in alle
        assert 10054 not in alle


# ---------------------------------------------------------------------------
# Scan-Policy
# ---------------------------------------------------------------------------

class TestCreateScanPolicy:
    def _patcher(self, zap, installed=None, existing_policies=None,
                 add_fails_with=None, calls=None):
        recorded = calls if calls is not None else []

        def mock_get(path, params=None):
            recorded.append((path, dict(params or {})))
            if path == "/JSON/ascan/action/addScanPolicy/" and add_fails_with:
                raise add_fails_with
            if path == "/JSON/ascan/view/scanners/":
                return {"scanners": [{"id": str(i)} for i in (installed or [])]}
            if path == "/JSON/ascan/view/scanPolicyNames/":
                return {"scanPolicyNames": list(existing_policies or [])}
            return {}

        return patch.object(zap, "_get", side_effect=mock_get)

    def test_already_exists_ist_kein_fehler(self, zap):
        calls = []
        err = ZapError("ZAP API error 400: already_exists",
                       endpoint="/JSON/ascan/action/addScanPolicy/",
                       zap_code="already_exists")
        with self._patcher(zap, installed=[40012], existing_policies=["p1"],
                           add_fails_with=err, calls=calls):
            enabled = zap.create_scan_policy("p1", ["xss"], "standard")
        assert enabled == {40012}
        assert any(p == "/JSON/ascan/action/enableScanners/" for p, _ in calls)

    def test_anderer_fehler_wird_durchgereicht(self, zap):
        err = ZapError("ZAP API error 400: illegal_parameter",
                       endpoint="/JSON/ascan/action/addScanPolicy/",
                       zap_code="illegal_parameter")
        with self._patcher(zap, add_fails_with=err):
            with pytest.raises(ZapError):
                zap.create_scan_policy("p:1", ["xss"], "standard")

    def test_unbekannte_ids_gehen_nicht_an_zap(self, zap):
        calls = []
        with self._patcher(zap, installed=[40012], existing_policies=["p1"],
                           calls=calls):
            zap.create_scan_policy("p1", ["xss"], "standard")
        enable = [params for path, params in calls
                  if path == "/JSON/ascan/action/enableScanners/"]
        assert enable and enable[0]["ids"] == "40012"
        assert zap.last_dropped_scanner_ids

    def test_fehlende_policy_nach_anlage_wirft(self, zap):
        with self._patcher(zap, installed=[40012],
                           existing_policies=["etwas-anderes"]):
            with pytest.raises(ZapError) as excinfo:
                zap.create_scan_policy("p1", ["xss"], "standard")
        assert excinfo.value.zap_code == "policy_missing_after_create"

    def test_policy_namen_liste_als_string(self, zap):
        with patch.object(zap, "_get",
                          return_value={"scanPolicyNames": '["Default Policy", "p1"]'}):
            assert zap.get_scan_policy_names() == ["Default Policy", "p1"]


# ---------------------------------------------------------------------------
# Fehlerkoerper
# ---------------------------------------------------------------------------

class TestZapErrorBody:
    def test_code_wird_ausgelesen(self, zap):
        resp = MagicMock(
            status_code=400,
            text='{"code":"does_not_exist","message":"Does Not Exist",'
                 '"detail":"scanPolicyName"}',
        )
        resp.raise_for_status = MagicMock(side_effect=requests.HTTPError("400"))
        with patch.object(zap.session, "get", return_value=resp):
            with pytest.raises(ZapError) as excinfo:
                zap._get("/JSON/ascan/action/scan/", {"url": "https://x"})
        err = excinfo.value
        assert err.zap_code == "does_not_exist"
        assert err.http_status == 400
        assert "scanPolicyName" in str(err)

    def test_produktionsfehler_ohne_detail(self, zap):
        # Genau der Text aus den 42 Produktionsscans.
        resp = MagicMock(
            status_code=400,
            text='{"code":"does_not_exist","message":"Does Not Exist"}',
        )
        resp.raise_for_status = MagicMock(side_effect=requests.HTTPError("400"))
        with patch.object(zap.session, "get", return_value=resp):
            with pytest.raises(ZapError) as excinfo:
                zap._get("/JSON/ascan/action/scan/", {"url": "https://x"})
        err = excinfo.value
        assert err.zap_code == "does_not_exist"
        assert err.endpoint == "/JSON/ascan/action/scan/"

    def test_nicht_json_bleibt_rohtext(self, zap):
        resp = MagicMock(status_code=500, text="Internal Server Error")
        resp.raise_for_status = MagicMock(side_effect=requests.HTTPError("500"))
        with patch.object(zap.session, "get", return_value=resp):
            with pytest.raises(ZapError) as excinfo:
                zap._get("/JSON/core/view/version/", None)
        assert excinfo.value.zap_code is None
        assert "Internal Server Error" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Kontext und Site-Tree
# ---------------------------------------------------------------------------

class TestContextUndSiteTree:
    def test_context_exists_true(self, zap):
        with patch.object(zap, "get_context_list", return_value=["ctx-a", "ctx-b"]):
            assert zap.context_exists("ctx-b") is True

    def test_context_exists_bei_fehler_false(self, zap):
        with patch.object(zap, "get_context_list",
                          side_effect=ZapError("weg", endpoint="/x")):
            assert zap.context_exists("ctx-b") is False

    def test_access_url_ruft_core_action(self, zap):
        with patch.object(zap, "_get", return_value={}) as mock_get:
            zap.access_url("https://example.com")
        path, params = mock_get.call_args[0]
        assert path == "/JSON/core/action/accessUrl/"
        assert params["url"] == "https://example.com"


# ---------------------------------------------------------------------------
# S0b-Nachtrag: Active-Scan-Poll-Timeout konfigurierbar und ueber ZAP-Cap
# ---------------------------------------------------------------------------

class TestActiveScanTimeout:
    """Der Poll-Timeout muss ueber ZAPs maxScanDurationInMins (720s) liegen.

    Sonst gibt der Poll auf, bevor ZAPs eigenes Limit den Scan sauber beendet,
    und ein erfolgreicher Lauf wird als 'timeout' verworfen. Lokal verifiziert
    (ZAP 2.17.0): beim Cap meldet ascan/view/status 100, poll_until_complete
    greift.
    """

    def test_default_liegt_ueber_zap_cap(self, monkeypatch):
        from scanner.phase2 import _zap_active_scan_timeout
        monkeypatch.delenv("ZAP_ACTIVE_SCAN_TIMEOUT_SEC", raising=False)
        # ZAP-Cap in docker-compose: maxScanDurationInMins=12 -> 720s
        assert _zap_active_scan_timeout() > 720

    def test_env_uebersteuert(self, monkeypatch):
        from scanner.phase2 import _zap_active_scan_timeout
        monkeypatch.setenv("ZAP_ACTIVE_SCAN_TIMEOUT_SEC", "1200")
        assert _zap_active_scan_timeout() == 1200

    def test_ungueltig_faellt_auf_default(self, monkeypatch):
        from scanner.phase2 import _zap_active_scan_timeout
        monkeypatch.setenv("ZAP_ACTIVE_SCAN_TIMEOUT_SEC", "abc")
        assert _zap_active_scan_timeout() == 900

    def test_untergrenze(self, monkeypatch):
        from scanner.phase2 import _zap_active_scan_timeout
        monkeypatch.setenv("ZAP_ACTIVE_SCAN_TIMEOUT_SEC", "5")
        assert _zap_active_scan_timeout() == 60
