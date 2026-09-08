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
        # stats.py reads capture_thinking off the responses, not the config, so a
        # campaign that claims it has to actually carry the block.
        resp = "<thinking>\npienso\n</thinking>\n\nrespondo" if "capture_thinking" in cfg else "respondo"
        for i in range(20):
            con.execute(
                "INSERT INTO attacks (campaign_id, seed_id, vector, language, response,"
                " score, evaluator_reasoning) VALUES (?,?,?,?,?,?,?)",
                (cid, f"S-{i:03d}", f"V{i % 2 + 1:02d}_v", "es-ES", resp,
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


class TestTheTwoJudgeQuestionsStaySeparate:
    """Autoevaluarse y "¿coincide otro juez?" son preguntas distintas."""

    @pytest.fixture
    def two_alts(self, tmp_path):
        """alpha y beta bajo Haiku, más un re-juicio de cada una y un autojuicio."""
        path = tmp_path / "j.db"
        con = sqlite3.connect(path)
        con.executescript(SCHEMA)
        base = {"model": "haiku", "provider": "litellm"}
        setup = [(1, "alpha", base, 4), (2, "beta", base, 8),
                 (3, "alpha", {"model": "segundo-juez"}, 6),
                 (4, "beta", {"model": "segundo-juez"}, 9),
                 (5, "beta", {"model": "beta"}, 14)]      # se juzga a sí misma
        for cid, target, judge, leaks in setup:
            con.execute("INSERT INTO campaigns VALUES (?,?,?,?)",
                        (cid, f"c{cid}", target,
                         json.dumps({"target": {"model": target, **BENCH_TARGET},
                                     "evaluator": judge})))
            for i in range(20):
                con.execute(
                    "INSERT INTO attacks (campaign_id, seed_id, vector, language,"
                    " response, score, evaluator_reasoning) VALUES (?,?,?,?,?,?,?)",
                    (cid, f"S-{i:03d}", "V01_v", "es-ES", "r",
                     9 if i < leaks else 0, "[blocked] ok"))
        con.commit()
        con.close()
        return path

    def test_the_self_judged_model_does_not_appear_as_a_second_opinion(self, two_alts):
        alt = section(run(two_alts), "A second judge")
        assert "segundo-juez" in alt
        assert "| beta | beta" not in alt, "juzgarse a sí mismo no es otra opinión"

    def test_the_second_judge_section_uses_one_judge_for_every_row(self, two_alts):
        """Una tanda de re-juicio que agota su cuota deja unos targets con un juez

        y otros con otro. Mezclarlos en una tabla son dos medias opiniones leídas
        como una, y las filas no lo dicen.
        """
        alt = section(run(two_alts), "A second judge")
        judges = {ln.split("|")[2].strip() for ln in alt.splitlines()
                  if ln.startswith("| ") and "---" not in ln and "Judge" not in ln}
        assert judges == {"haiku", "segundo-juez"}, judges


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


class TestDegradedJudge:
    """Un juez que se cae escribe filas que parecen veredictos y no lo son."""

    @pytest.fixture
    def dead(self, tmp_path):
        """alpha juzgada tres veces: limpia, con un fallback, y medio muerta."""
        path = tmp_path / "d.db"
        con = sqlite3.connect(path)
        con.executescript(SCHEMA)
        # (id, target, juez, desde qué índice el juez falla)
        setup = [(1, "alpha", NEUTRAL_JUDGE, 99),
                 (2, "beta", NEUTRAL_JUDGE, 99),
                 (3, "alpha", {"model": "juez-con-hipo"}, 19),   # 1/20 = 5%, se queda
                 (4, "alpha", {"model": "juez-muerto"}, 8)]      # 12/20 = 60%, fuera
        for cid, target, judge, fb_from in setup:
            con.execute("INSERT INTO campaigns VALUES (?,?,?,?)",
                        (cid, f"scan_{target}_{cid}", target,
                         json.dumps({"target": {"model": target, **BENCH_TARGET},
                                     "evaluator": judge})))
            for i in range(20):
                dead = i >= fb_from
                con.execute(
                    "INSERT INTO attacks (campaign_id, seed_id, vector, language,"
                    " response, score, evaluator_reasoning) VALUES (?,?,?,?,?,?,?)",
                    (cid, f"S-{i:03d}", "V01_v", "es-ES", "r",
                     10 if dead else (9 if i < 4 else 0),
                     "[FALLBACK — Judge error: RateLimitError]" if dead else "[blocked] ok"))
        con.commit()
        con.close()
        return path

    def test_keyword_scores_are_not_counted_as_verdicts(self, dead):
        """La campaña 3 tiene 4 fugas reales y un fallback que puntúa 10.

        Contando el fallback son 5 de 20, el 25%. Sin contarlo, 4 de 19: 21,1%.
        """
        alt = section(run(dead), "A second judge")
        assert "| 4 / 19 | 21.1% |" in alt
        assert "5 / 20" not in alt

    def test_the_half_dead_campaign_is_named_and_dropped(self, dead):
        out = run(dead)
        disclosure = section(out, "Verdicts the judge never gave")
        assert "| 4 | alpha | juez-muerto | 12 (60%) | 20 | **yes** |" in disclosure
        assert "| 3 | alpha | juez-con-hipo | 1 (5%) | 20 | no |" in disclosure
        assert "juez-muerto" not in section(out, "A second judge"), "no juzgó, no opina"

    def test_a_clean_database_says_so(self, db):
        assert "Every score in this database came from a judge" in section(
            run(db), "Verdicts the judge never gave")


class TestConfigVersusData:
    def test_what_the_responses_say_beats_what_the_config_claims(self, tmp_path):
        """El config guarda la intención; sólo las respuestas dicen qué pasó.

        Hasta v0.6.0 el target leía capture_thinking y no se lo pasaba al
        proveedor, así que hay campañas cuyo config promete un bloque de
        razonamiento que no está. Creerse el config las hace comparables con las
        que sí lo capturaron, y la diferencia entre ver el razonamiento y no verlo
        se publica como si fuera otra cosa.
        """
        path = tmp_path / "m.db"
        con = sqlite3.connect(path)
        con.executescript(SCHEMA)
        for cid, target, resp in [(1, "alpha", "respondo"),
                                  (2, "beta", "<thinking>\npienso\n</thinking>\n\nrespondo")]:
            con.execute("INSERT INTO campaigns VALUES (?,?,?,?)",
                        (cid, f"scan_{target}_{cid}", target,
                         _config(target, capture_thinking=True)))
            for i in range(20):
                con.execute(
                    "INSERT INTO attacks (campaign_id, seed_id, vector, language,"
                    " response, score, evaluator_reasoning) VALUES (?,?,?,?,?,?,?)",
                    (cid, f"S-{i:03d}", "V01_v", "es-ES", resp, 0, "[blocked] ok"))
        con.commit()
        con.close()
        out = run(path)
        assert "nothing to compare head to head" in out, (
            "una capturó razonamiento y la otra no: no son el mismo experimento")
        assert "Campaigns whose config does not match what they did:** 1" in out

    def test_a_rejudge_arm_is_not_flagged_as_misdescribed(self, tmp_path):
        """Un brazo answer-only guarda la respuesta sin razonamiento, y es correcto."""
        path = tmp_path / "r.db"
        con = sqlite3.connect(path)
        con.executescript(SCHEMA)
        cfg = json.loads(_config("alpha", capture_thinking=True))
        cfg["rejudge"] = {"source_campaign": 9, "arm": "answer"}
        con.execute("INSERT INTO campaigns VALUES (1,'rejudge_answer_alpha','alpha',?)",
                    (json.dumps(cfg),))
        con.execute("INSERT INTO attacks (campaign_id, seed_id, vector, language,"
                    " response, score, evaluator_reasoning)"
                    " VALUES (1,'S-1','V01_v','es-ES','respondo',0,'[blocked] ok')")
        con.commit()
        con.close()
        assert "does not match what they did" not in run(path)


class TestLanguageUnderEachJudge:
    """La defensa del hallazgo de idiomas: las mismas respuestas, varios jueces.

    Las tasas de la fixture están elegidas para que cada forma de estropearlo dé
    un número distinto: 45,0% si está bien, 47,6% si se cuela la prueba de humo,
    30,0% si se mezcla un brazo que juzgó otro texto.
    """

    @pytest.fixture
    def judged_thrice(self, tmp_path):
        path = tmp_path / "l.db"
        con = sqlite3.connect(path)
        con.executescript(SCHEMA)

        def add(cid, target, judge, leaks, n=20, rejudge=None, arm="full"):
            cfg = {"target": {"model": target, **BENCH_TARGET},
                   "evaluator": {"model": judge}}
            if rejudge:
                cfg["rejudge"] = {"source_campaign": rejudge, "arm": arm}
            con.execute("INSERT INTO campaigns VALUES (?,?,?,?)",
                        (cid, f"c{cid}", target, json.dumps(cfg)))
            for i in range(n):
                con.execute(
                    "INSERT INTO attacks (campaign_id, seed_id, vector, language,"
                    " response, score, evaluator_reasoning) VALUES (?,?,?,?,?,?,?)",
                    (cid, f"S-{i:03d}", "V01_v", "ca-ES" if i % 2 else "es-ES", "r",
                     9 if i < leaks else 0, "[blocked] ok"))

        add(1, "alpha", "haiku", 4)
        add(2, "beta", "haiku", 8)                        # haiku: 6/20 por idioma
        add(3, "alpha", "segundo", 6, rejudge=1)
        add(4, "beta", "segundo", 12, rejudge=2)          # segundo: 9/20 por idioma
        add(5, "alpha", "segundo", 3, n=3, rejudge=1)     # prueba de humo
        add(6, "alpha", "segundo", 0, rejudge=1, arm="answer")   # otro texto
        con.commit()
        con.close()
        return path

    def _row(self, db, locale):
        for line in section(run(db), "By language, under each judge").splitlines():
            if line.startswith(f"| {locale} |"):
                return line
        raise AssertionError(f"no hay fila para {locale}")

    def test_the_rates_are_what_the_full_campaigns_say(self, judged_thrice):
        assert self._row(judged_thrice, "ca-ES") == "| ca-ES | 30.0% | 45.0% |"
        assert self._row(judged_thrice, "es-ES") == "| es-ES | 30.0% | 45.0% |"

    def test_a_three_row_smoke_test_is_not_pooled_with_the_real_ones(self, judged_thrice):
        """`--limit 3` deja una campaña más, con el mismo juez y tres filas.

        Sumarla mete un puñado de veredictos bajo el mismo encabezado que 40, y
        aquí subiría el catalán de 45,0% a 47,6%.
        """
        assert "47.6%" not in self._row(judged_thrice, "ca-ES")

    def test_an_answer_only_arm_is_not_a_second_opinion(self, judged_thrice):
        """Ese brazo juzgó otro texto: no es el mismo juicio sobre lo mismo."""
        assert "30.0% | 30.0%" not in self._row(judged_thrice, "ca-ES")

    def test_it_prints_an_ordering_per_judge(self, judged_thrice):
        sec = section(run(judged_thrice), "By language, under each judge")
        assert "- **haiku**:" in sec
        assert "- **segundo**:" in sec

    def test_one_judge_only_says_there_is_nothing_to_compare(self, db):
        assert "nothing to compare" in section(run(db), "By language, under each judge")
