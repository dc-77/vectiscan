# -*- coding: utf-8 -*-
"""Bildnachweise: Aufloesung, Platzhalter, Ausfall von MinIO."""
from __future__ import annotations

from reporter.pdf.v3 import render_html, screenshots as S
from reporter.pdf.v3.render import PLACEHOLDER
from tests.pdf_v3.conftest import JUNKERWERK_MULTI, fake_screenshots
from tests.v3.conftest import data_for

PNG = b"\x89PNG\r\n\x1a\n"


class FakeMinio:
    """Nur so viel MinIO, wie der Resolver anfasst."""

    def __init__(self, objects: dict[str, bytes], fehler: Exception | None = None):
        self._objects = objects
        self._fehler = fehler
        self.calls: list[str] = []

    def get_object(self, bucket: str, key: str):
        self.calls.append(key)
        if self._fehler:
            raise self._fehler
        if key not in self._objects:
            raise KeyError(key)
        return _Response(self._objects[key])


class _Response:
    def __init__(self, data: bytes):
        self._data = data
        self.closed = False

    def read(self) -> bytes:
        return self._data

    def close(self) -> None:
        self.closed = True

    def release_conn(self) -> None:
        pass


def test_platzhalter_liegt_als_paketressource_vor():
    assert PLACEHOLDER.exists()
    svg = PLACEHOLDER.read_text(encoding="utf-8")
    assert "viewBox" in svg          # intrinsisches Seitenverhaeltnis, sonst kippt das Raster
    assert "nicht verf" in svg


def test_ohne_resolver_gibt_es_keine_bilder():
    assert S.no_screenshots("egal") is None
    assert S.available([{"key": "a"}, {"key": "b"}], S.no_screenshots) is False


def test_available_reicht_ein_bild():
    def nur_eins(key: str) -> bytes | None:
        return PNG if key == "b" else None

    assert S.available([{"key": "a"}, {"key": "b"}], nur_eins) is True


def test_minio_resolver_cached_und_faengt_fehler():
    client = FakeMinio({"o/1.png": PNG})
    resolver = S.MinioScreenshots(client)
    assert resolver("o/1.png") == PNG
    assert resolver("o/1.png") == PNG
    assert client.calls == ["o/1.png"], "zweiter Zugriff kommt aus dem Cache"
    assert resolver("o/fehlt.png") is None


def test_minio_ausfall_kippt_den_bericht_nicht():
    resolver = S.MinioScreenshots(FakeMinio({}, fehler=OSError("MinIO weg")))
    assert resolver("o/1.png") is None


def test_downscale_laesst_nichtbilder_in_ruhe():
    assert S.downscale(b"kein bild") == b"kein bild"


def test_kapitel_34_entfaellt_ohne_jedes_bild():
    html, _variant, warnungen = render_html(data_for(JUNKERWERK_MULTI))
    assert "3.4 Gesichtete Web-Oberflächen" not in html
    assert any("Kapitel 3.4" in w for w in warnungen)


def test_kapitel_34_erscheint_mit_bildern():
    html, _variant, warnungen = render_html(data_for(JUNKERWERK_MULTI),
                                            resolver=fake_screenshots)
    assert "3.4 Gesichtete Web-Oberflächen" in html
    assert warnungen == []
    assert "vectiscan-screenshot:" in html


def test_bildverweis_traegt_den_vollen_schluessel():
    """Der Basisname reicht bei Berichten ueber mehrere Laeufe nicht."""
    data = data_for(JUNKERWERK_MULTI)
    html = render_html(data, resolver=fake_screenshots)[0]
    for shot in data.architecture.screens:
        assert shot.key, "reporter/v3 muss den MinIO-Schluessel mitgeben"
        assert shot.key.startswith(JUNKERWERK_MULTI + "/")
        assert f"vectiscan-screenshot:{shot.key}" in html
