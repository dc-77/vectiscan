"""Swarm-Stack (stack.yml, ci/swarm.yml): was sonst erst im Cluster auffiele.

Swarm-Umzug, 06.10.2026. Laeuft im CI-Job test-edge neben
test_edge_admin_guard.py und test_compose_images.py (pyyaml, pytest).

Geprueft wird die Stack-Datei so, wie der Deploy-Job sie je Feld ausrollt: die
Variablen aus swarm:deploy:test und swarm:deploy:prod werden eingesetzt. Die
Router-Invarianten sind dieselben wie fuer docker-compose.yml und kommen aus
test_edge_admin_guard.py, damit es fuer den Admin-Schutz nur eine Quelle gibt.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

import test_edge_admin_guard as edge

ROOT = Path(__file__).resolve().parents[1]
FELDER = ("swarm:deploy:test", "swarm:deploy:prod")
EINSPRUNG = ["/bin/sh", "/run/vectiscan/secrets-entrypoint.sh"]
_VAR = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


class _CiLoader(yaml.SafeLoader):
    """safe_load mit !reference, das GitLab kennt und PyYAML nicht."""


_CiLoader.add_constructor("!reference", lambda loader, node: loader.construct_sequence(node))


def _ci() -> dict:
    return yaml.load((ROOT / "ci" / "swarm.yml").read_text(encoding="utf-8"), Loader=_CiLoader)


def _stack() -> dict:
    return yaml.safe_load((ROOT / "stack.yml").read_text(encoding="utf-8"))


def _werte(feld: str) -> dict:
    return {k: str(v) for k, v in _ci()[feld]["variables"].items()}


def _einsetzen(text: str, werte: dict) -> str:
    def ersatz(m: re.Match) -> str:
        name, vorgabe = m.group(1), m.group(2)
        if name in werte:
            return werte[name]
        return vorgabe if vorgabe is not None else m.group(0)
    return _VAR.sub(ersatz, text)


def _labels(feld: str) -> dict[str, dict[str, str]]:
    werte = _werte(feld)
    out = {}
    for name, svc in _stack()["services"].items():
        d = {}
        for eintrag in ((svc or {}).get("deploy") or {}).get("labels") or []:
            k, v = _einsetzen(str(eintrag), werte).split("=", 1)
            d[k] = v
        out[name] = d
    return out


# --- Admin-Schutz, je Feld --------------------------------------------------

@pytest.mark.parametrize("feld", FELDER)
@pytest.mark.parametrize("svc,public_router,admin_router,prefix,requires_auth", edge.ADMIN_GUARD_PAIRS)
def test_admin_schutz_je_feld(feld, svc, public_router, admin_router, prefix, requires_auth):
    router = _werte(feld)["ROUTER"]
    labels = _labels(feld)[svc]
    oeffentlich = public_router.replace("vectiscan", router, 1)
    admin = admin_router.replace("vectiscan", router, 1)
    regel_o = labels[f"traefik.http.routers.{oeffentlich}.rule"]
    regel_a = labels[f"traefik.http.routers.{admin}.rule"]

    offen = set(edge._hosts_in_rule(regel_o)) - set(edge._hosts_in_rule(regel_a))
    assert not offen, f"{feld} {svc}: {sorted(offen)} ohne {prefix}-Schutz"
    assert edge._hosts_in_rule(regel_o), f"{feld} {svc}: keine Host-Regel eingesetzt: {regel_o}"
    if "||" in regel_a:
        assert re.match(r"^\(\s*Host\(.*\)\s*&&\s*Path(Prefix|Regexp)", regel_a), regel_a
    mw = labels[f"traefik.http.routers.{admin}.middlewares"]
    assert "internal-auth@file" not in mw and "oauth2-proxy-redirect@file" not in mw, mw
    assert int(labels[f"traefik.http.routers.{admin}.priority"]) > len(regel_o), (
        f"{feld} {svc}: Prioritaet des Admin-Routers nicht ueber der Laenge von {regel_o!r}")


def test_prod_bedient_alle_frontend_namen():
    regel = _labels("swarm:deploy:prod")["frontend"]["traefik.http.routers.vectiscan-prod-web.rule"]
    assert set(edge._hosts_in_rule(regel)) == {"scan.vectigal.tech", "vectiscan.de", "www.vectiscan.de"}


# --- Images -----------------------------------------------------------------

def test_eigene_images_aus_der_gitlab_registry_fremde_wie_auf_docker02():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    fremd_compose = {s["image"] for s in compose["services"].values() if "@sha256:" in s.get("image", "")}
    for name, svc in _stack()["services"].items():
        image = svc["image"]
        if image.startswith("${CI_REGISTRY_IMAGE}/"):
            assert image.endswith(":${TAG:-latest}"), f"{name}: {image}"
        else:
            assert image in fremd_compose, f"{name}: {image} weicht vom gepinnten Abbild in docker-compose.yml ab"


# --- Einsprungpunkt fuer die Secrets ------------------------------------------

def test_dienste_mit_secrets_starten_ueber_die_bruecke():
    for name, svc in _stack()["services"].items():
        if not svc.get("secrets"):
            continue
        assert svc.get("entrypoint") == EINSPRUNG, f"{name}: ohne Bruecke sieht die Anwendung keine Secrets"
        # Ein eigenes entrypoint ersetzt den des Images samt CMD.
        assert svc.get("command"), f"{name}: ohne command startet nur die Bruecke"
        ziele = [c.get("target") for c in svc.get("configs") or []]
        assert EINSPRUNG[1] in ziele, f"{name}: Config mit dem Einsprungskript fehlt"


def test_einsprungskript_mit_lf_und_exec():
    roh = (ROOT / "deploy" / "swarm" / "secrets-entrypoint.sh").read_bytes()
    assert b"\r\n" not in roh, "CRLF: /bin/sh im Container scheitert daran"
    assert b'exec "$@"' in roh


def test_secret_vars_und_secrets_block_decken_sich():
    stack = _stack()
    namen = {str(s["name"]).removeprefix("${SECRET_").removesuffix("}") for s in stack["secrets"].values()}
    secret_vars = set(_ci()[".vs:swarm"]["variables"]["SECRET_VARS"].split())
    assert namen == secret_vars
    for name, svc in stack["services"].items():
        for s in svc.get("secrets") or []:
            assert s in stack["secrets"], f"{name}: Secret {s} fehlt oben"


# --- Repliken und ZAP-Paarung --------------------------------------------------

def test_genau_eine_api():
    # Scheduler, Mailversand und Migrationen beim Start vertragen keine zweite
    # Instanz (Kopf von stack.yml).
    assert _stack()["services"]["api"]["deploy"]["replicas"] == 1


def test_jeder_scan_worker_hat_seinen_zap():
    stack = _stack()
    env = stack["services"]["scan-worker"]["environment"]
    assert env["ZAP_BASE_URL"] == "http://zap-{{.Task.Slot}}:8090"
    zaps = {n for n in stack["services"] if re.fullmatch(r"zap-\d+", n)}
    for feld in FELDER:
        n = int(_werte(feld)["REPLICAS"])
        fehlend = {f"zap-{i}" for i in range(1, n + 1)} - zaps
        assert not fehlend, f"{feld}: {n} Scan-Worker, aber {sorted(fehlend)} fehlt"


def test_prod_mit_drei_repliken():
    assert _werte("swarm:deploy:prod")["REPLICAS"] == "3"


def test_precheck_mit_begrenzter_parallelitaet():
    # Jeder Thread oeffnet eigene Verbindungen; 3 Repliken x 20 wie auf
    # docker02 sprengten das Budget der Instanz (docs/UMZUG-swarm.md, 1.1).
    env = _stack()["services"]["precheck-worker"]["environment"]
    assert env["PRECHECK_CIDR_MAX_PARALLEL"] == "${PRECHECK_CIDR_MAX_PARALLEL:-10}"


def test_ueberwachung_und_anmeldung_kommen_von_der_plattform():
    # Entscheidung 06.10.2026: Stack monitoring und Stack identity statt
    # eigener Instanzen. Kehrt einer davon in die Stack-Datei zurueck, laeuft
    # er doppelt neben der Plattform.
    eigene = {"uptime-kuma", "loki", "promtail", "grafana", "keycloak", "keycloak-db", "oauth2-proxy"}
    assert not eigene & set(_stack()["services"])


# --- Trennung der Felder -------------------------------------------------------

def test_testfeld_traegt_kein_prod_merkmal():
    test = _werte("swarm:deploy:test")
    assert test["MINIO_BUCKET_PREFIX"] == "vect-test-"
    assert test["REDIS_EVENT_PREFIX"] == "vect-test:"
    assert ":5432/" in test["FELD_PRUEFUNG"] and "_test_" in test["FELD_PRUEFUNG"]
    assert "SWARM_CRM_WEBHOOK_URL" not in test


def test_stack_liest_nicht_die_ungescopte_crm_adresse():
    # CRM_WEBHOOK_URL gibt es als Projektvariable mit der Prod-Adresse (VEC-304).
    text = (ROOT / "stack.yml").read_text(encoding="utf-8")
    code = "\n".join(z for z in text.splitlines() if not z.lstrip().startswith("#"))
    assert "${CRM_WEBHOOK_URL" not in code
