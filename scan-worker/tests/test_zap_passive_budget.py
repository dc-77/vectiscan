"""Das Warten auf die ZAP-Passiv-Queue bekommt nur einen Anteil am Budget.

Nach dem Paginierungs-Fix (Auftrag 419e00cc, rankingcoach, 15 Hosts) waren die
Befunde je Host vollstaendig, der Auftrag lief aber in das Zeitlimit von 120
Minuten: das Warten faellt je Host an, und 300 Sekunden mal 15 Hosts sprengen
jedes Gesamtbudget. Vollstaendige Befunde auf einem Host, der den Auftrag
scheitern laesst, sind nichts wert.
"""

import time
from unittest.mock import MagicMock

import pytest

from scanner.tools.zap_client import (
    PASSIVE_WAIT_BUDGET_SHARE,
    PASSIVE_WAIT_MIN_TIMEOUT,
    PASSIVE_WAIT_TIMEOUT,
    passive_wait_budget,
)

from .test_zap_recovery_fix import _mock_zap, _phase2_mit


class TestBudgetRechnung:
    def test_der_rankingcoach_fall_passt_ins_budget(self):
        """15 Hosts, zwei gleichzeitig, 120 Minuten: das Warten muss passen."""
        je_host = passive_wait_budget(7200, 15, 2)
        wellen = 8  # ceil(15 / 2)

        assert je_host < PASSIVE_WAIT_TIMEOUT, "ungedeckelt wie vor dem Fix"
        assert je_host * wellen <= 7200 * PASSIVE_WAIT_BUDGET_SHARE + wellen

    def test_wenige_hosts_bekommen_die_volle_obergrenze(self):
        """Ein einzelner Host kann sich das lange Warten leisten."""
        assert passive_wait_budget(7200, 1, 1) == PASSIVE_WAIT_TIMEOUT

    def test_niemals_unter_dem_mindestwert(self):
        """Unter dem Mindestwert hat das Warten keinen Zweck mehr."""
        assert passive_wait_budget(60, 50, 1) == PASSIVE_WAIT_MIN_TIMEOUT

    @pytest.mark.parametrize("args", [(0, 15, 2), (7200, 0, 2), (7200, 15, 0),
                                      (-1, 15, 2)])
    def test_unbrauchbare_angaben_fallen_offen_aus(self, args):
        """Fail-open: kaputte Zahlen duerfen das Warten nicht abwuergen."""
        assert passive_wait_budget(*args) == PASSIVE_WAIT_TIMEOUT

    def test_mehr_hosts_bedeuten_kuerzeres_warten(self):
        """Die Aufteilung reagiert ueberhaupt auf die Zahl der Hosts."""
        assert passive_wait_budget(7200, 30, 2) < passive_wait_budget(7200, 15, 2)


class TestPhase2NutztDasBudget:
    def test_vorgegebenes_budget_wird_verwendet(self, tmp_path):
        zap = _mock_zap()

        _phase2_mit(zap, "bbbbbbbb-0001", tmp_path, passive_wait_timeout=135)

        zap.wait_for_passive_scan.assert_called()
        for call in zap.wait_for_passive_scan.call_args_list:
            assert call.kwargs["timeout"] == 135

    def test_restbudget_deckelt_zusaetzlich(self, tmp_path):
        """Ein fast abgelaufener Auftrag wartet nicht noch die vollen 135 s."""
        zap = _mock_zap()

        _phase2_mit(zap, "bbbbbbbb-0002", tmp_path, passive_wait_timeout=135,
                    deadline_monotonic=time.monotonic() + 10)

        for call in zap.wait_for_passive_scan.call_args_list:
            assert call.kwargs["timeout"] <= PASSIVE_WAIT_MIN_TIMEOUT

    def test_abgelaufenes_budget_wartet_nicht_endlos(self, tmp_path):
        """Deadline schon vorbei: Mindestwert, nicht die Obergrenze."""
        zap = _mock_zap()

        _phase2_mit(zap, "bbbbbbbb-0003", tmp_path, passive_wait_timeout=135,
                    deadline_monotonic=time.monotonic() - 500)

        for call in zap.wait_for_passive_scan.call_args_list:
            assert call.kwargs["timeout"] == PASSIVE_WAIT_MIN_TIMEOUT


class TestWaitForPassiveScanReichtDurch:
    def test_zeitlimit_geht_an_die_abfrage(self):
        """Das uebergebene Zeitlimit landet wirklich in poll_until_complete."""
        from scanner.tools.zap_client import ZapClient

        zap = ZapClient.__new__(ZapClient)
        zap.poll_until_complete = MagicMock(return_value=True)

        ZapClient.wait_for_passive_scan(zap, timeout=99)

        assert zap.poll_until_complete.call_args.kwargs["timeout"] == 99
