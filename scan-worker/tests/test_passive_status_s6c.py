"""S6c (spec/09 #35, spec/10 R6, spec/11 7b): Passivquellen-Status und -Export."""

from unittest.mock import patch

from scanner.passive.abuseipdb_client import AbuseIPDBClient


def test_abuseipdb_exportiert_max_age_in_days() -> None:
    """maxAgeInDays gehoert in den Export, sonst ist totalReports ohne Bezug."""
    client = AbuseIPDBClient.__new__(AbuseIPDBClient)
    client.api_key = "x"
    payload = {"data": {"abuseConfidenceScore": 0, "totalReports": 5,
                        "isp": "Hetzner Online GmbH", "usageType": "Data Center"}}
    with patch.object(AbuseIPDBClient, "available", True), \
         patch.object(AbuseIPDBClient, "_get", return_value=payload):
        r = client.check_ip("116.202.77.64", max_age_days=90)
    assert r["maxAgeInDays"] == 90
    assert r["totalReports"] == 5
