"""Tests para scripts/stats.py — el script que genera todas las cifras publicadas.

Nada más del proyecto se lee tanto como docs/RESULTS.md, y hasta ahora nada lo
cubría. Las dos veces que este script se equivocó no falló: imprimió una tabla
con el aspecto de siempre y un número distinto dentro.
"""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "stats.py"

SCHEMA = """
CREATE TABLE campaigns (id INTEGER PRIMARY KEY, name TEXT, target_model TEXT,
                        config TEXT);
CREATE TABLE attacks (id INTEGER PRIMARY KEY, campaign_id INTEGER, seed_id TEXT,
                      vector TEXT, owasp TEXT, atlas TEXT, language TEXT,
                      prompt TEXT, response TEXT, chunks_retrieved TEXT,
                      score INTEGER, success INTEGER, evaluator_reasoning TEXT,
                      timestamp TEXT, duration_ms INTEGER);
"""

BENCH_TARGET = {"embed_model": "nomic-embed-text", "retriever_k": 3,
                "temperature": 0.3, "num_predict": 512,
                "system_prompt": "eres un bot"}
NEUTRAL_JUDGE = {"model": "judge-model", "provider": "litellm"}


def _config(model, judge=None, **target_overrides):
    return json.dumps({
        "target": {"model": model, **BENCH_TARGET, **target_overrides},
        "evaluator": judge or NEUTRAL_JUDGE,
    })


@pytest.fixture
def db(tmp_path):
    """Un benchmark de dos targets más los tres experimentos que lo contaminan."""
    path = tmp_path / "t.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)

    # (campaign_id, target, config, cuántas de las 20 semillas filtran)
    #
    # Los experimentos llevan los ids bajos a propósito. El desempate elige la
    # campaña más antigua, así que si la agrupación deja pasar un experimento,
    # este lo elige a él y no al benchmark: el test falla por la razón correcta
    # en vez de salvarse por el orden.
    setup = [
        (1, "beta", _config("beta", capture_thinking=True), 16),        # experimento
        (2, "beta", _config("beta", judge={"model": "beta"}), 18),      # se autojuzga
        (3, "alpha", _config("alpha"), 4),                              # benchmark
        (4, "beta", _config("beta"), 8),                                # benchmark
        (5, "beta", _config("beta"), 9),                                # repetición
    ]
    for cid, target, cfg, leaks in setup:
        con.execute("INSERT INTO campaigns VALUES (?,?,?,?)",
                    (cid, f"scan_{target}_{cid}", target, cfg))
        for i in range(20):
            con.execute(
                "INSERT INTO attacks (campaign_id, seed_id, vector, language, score,"
                " evaluator_reasoning) VALUES (?,?,?,?,?,?)",
                (cid, f"S-{i:03d}", f"V{i % 2 + 1:02d}_v", "es-ES",
                 9 if i < leaks else 0, ""))
    con.commit()
    con.close()
    return path


def run(db):
    out = subprocess.run([sys.executable, str(SCRIPT), str(db)],
                         capture_output=True, text=True, check=True)
    return out.stdout


def section(text, header):
    body = text.split(f"### {header}")[1]
    return body.split("\n### ")[0]


class TestHeadToHead:
    def test_excludes_the_experiments_that_share_the_seeds(self, db):
        """Un experimento no puede colarse en el ranking de modelos.

        Las cuatro campañas de `beta` disparan las mismas semillas, así que
        agrupar por semillas las hace intercambiables y la que gane el orden se
        publica como si fuera el benchmark. Aquí eso serían 80% o 90% en vez
        del 40% real.
        """
        h2h = section(run(db), "Head-to-head")
        assert "2 targets" in h2h
        assert "| alpha | 20 | 20.0% |" in h2h
        assert "| beta | 20 | 40.0% |" in h2h
        for wrong in ("80.0%", "90.0%", "45.0%"):
            assert wrong not in h2h

    def test_language_rates_come_from_the_comparable_set_only(self, db):
        """La tabla de idiomas es el titular del proyecto.

        Sobre las cinco campañas el es-ES sale al 55%; sobre las dos comparables,
        al 30%. La diferencia es una campaña que se puntúa a sí misma.
        """
        out = run(db)
        raw = section(out, "By language, raw")
        assert "| es-ES | 40 |" in raw, "solo las dos campañas comparables"
        assert "30.0%" in raw
        assert "comparable campaigns" in raw

    def test_repeat_of_the_same_config_is_still_found(self, db):
        """Excluir experimentos no puede cargarse la medida de varianza."""
        var = section(run(db), "Run-to-run variance")
        # 8 y 9 fugas sobre 20 semillas: un veredicto cambiado, el 5%
        assert "| beta | 40.0% | 45.0% | 1 / 20 (5.0%) | 95.0% |" in var

    def test_self_judged_campaign_is_found_as_judge_bias(self, db):
        bias = section(run(db), "Judge bias")
        assert "**(self)**" in bias
        assert "18 / 20" in bias


class TestEmptySections:
    def test_no_multiturn_says_so_instead_of_an_empty_table(self, db):
        multi = section(run(db), "Multi-turn strategies")
        assert "No multi-turn campaigns" in multi
        assert "| Strategy |" not in multi

    def test_no_errors_says_so(self, db):
        err = section(run(db), "Errored attacks")
        assert "None." in err
        assert "| Target |" not in err


def test_runs_against_a_database_with_a_single_campaign(tmp_path):
    """Sin dos campañas comparables no hay ranking, y eso no es un error."""
    path = tmp_path / "one.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.execute("INSERT INTO campaigns VALUES (1,'solo','alpha',?)", (_config("alpha"),))
    con.execute("INSERT INTO attacks (campaign_id, seed_id, vector, language, score,"
                " evaluator_reasoning) VALUES (1,'S-1','V01_v','es-ES',9,'')")
    con.commit()
    con.close()
    assert "nothing to compare head to head" in run(path)


def test_overnight_agrees_with_stats_on_which_campaigns_are_comparable(db, monkeypatch):
    """Dos sitios deciden qué campañas son comparables. Tienen que decir lo mismo.

    overnight.py no importa stats.py — ese módulo imprime un informe entero al
    importarse — así que reimplementa la regla. Reimplementar una regla es la
    forma habitual de que dos sitios se separen sin que nadie se entere.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "overnight", Path(__file__).resolve().parent.parent / "scripts" / "overnight.py")
    overnight = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(overnight)
    except Exception as e:  # pragma: no cover - falta ollama/litellm en algún entorno
        pytest.skip(f"overnight.py no importable aquí: {e}")
    monkeypatch.setattr(overnight, "DB", db)

    from_stats = section(run(db), "Head-to-head")
    ids = overnight.benchmark_ids()
    assert ids == [3, 4], "los benchmarks son las campañas 3 y 4, no los experimentos"
    assert "2 targets" in from_stats
