"""Feld-Praefixe fuer den Swarm (06.10.2026).

Auf dem gemeinsamen Datenknoten trennen MINIO_BUCKET_PREFIX die Buckets und
REDIS_EVENT_PREFIX die Pub/Sub-Kanaele von vect-test und vect-prod. Ohne die
Variablen muss alles heissen wie bisher, sonst bricht docker02.
"""
import importlib

import pytest

from scanner import progress, upload


@pytest.fixture
def neu_laden(monkeypatch):
    def laden(**env):
        for name in ("MINIO_BUCKET_PREFIX", "REDIS_EVENT_PREFIX"):
            monkeypatch.delenv(name, raising=False)
        for name, wert in env.items():
            monkeypatch.setenv(name, wert)
        return importlib.reload(upload), importlib.reload(progress)
    yield laden
    monkeypatch.undo()
    importlib.reload(upload)
    importlib.reload(progress)


def test_ohne_praefix_wie_auf_docker02(neu_laden):
    up, pr = neu_laden()
    assert up.RAWDATA_BUCKET == "scan-rawdata"
    assert up.SCREENSHOTS_BUCKET == "scan-screenshots"
    assert pr._event_channel("abc") == "scan:events:abc"


def test_mit_feld_praefix(neu_laden):
    up, pr = neu_laden(MINIO_BUCKET_PREFIX="vect-test-", REDIS_EVENT_PREFIX="vect-test:")
    assert up.RAWDATA_BUCKET == "vect-test-scan-rawdata"
    assert up.SCREENSHOTS_BUCKET == "vect-test-scan-screenshots"
    assert pr._event_channel("abc") == "vect-test:scan:events:abc"
