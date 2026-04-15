"""Tests para vigia.reporting — Report Generator."""

import json
import os
import sqlite3
import tempfile
import pytest

from vigia.reporting.generator import ReportGenerator, CampaignData, AttackResult, _html_escape
from vigia.database import init_db, create_campaign, record_attack, finish_campaign


# ─── Helpers ─────────────────────────────────────────────────

def _make_attack(
    seed_id="S-001", vector="goal_hijacking", score=7, success=True,
    owasp="ASI01", language="es-ES", owasp_agentic=None,
    scores=None, violations=None,
):
    return AttackResult(
        seed_id=seed_id, vector=vector, owasp=owasp, language=language,
        prompt="test prompt", response="test response", score=score,
        success=success, reasoning="test reasoning", duration_ms=100,
        scores=scores or {}, violations=violations or [],
        owasp_agentic=owasp_agentic or [],
    )


def _make_campaign_data(attacks=None, name="Test Campaign", model="llama3.1:8b"):
    data = CampaignData(
        campaign_id=1, name=name, target_model=model,
        started_at="2026-03-23T10:00:00", finished_at="2026-03-23T10:05:00",
    )
    data.attacks = attacks or []
    data.compute_stats()
    return data


def _seed_db():
    """Crea una DB temporal con datos de prueba."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    conn = init_db(tmp.name)
    cid = create_campaign(conn, "test_campaign", "llama3.1:8b", {"test": True})

    # Ataque exitoso
    record_attack(conn, cid, {
        "seed_id": "DB-001", "vector": "goal_hijacking", "owasp": "ASI01",
        "language": "es-ES", "prompt": "prompt1", "response": "response1",
        "score": 8, "evaluator_reasoning": json.dumps({
            "scores": {"info_disclosure": 2, "goal_hijacking": 8, "overall": 8},
            "owasp_agentic": ["ASI01:AgentGoalHijacking"],
            "violations": [], "reasoning": "Agent was hijacked",
        }),
        "duration_ms": 150,
    })

    # Ataque seguro
    record_attack(conn, cid, {
        "seed_id": "DB-002", "vector": "tool_misuse", "owasp": "ASI02",
        "language": "es-ES", "prompt": "prompt2", "response": "response2",
        "score": 1, "evaluator_reasoning": "Agent refused correctly",
        "duration_ms": 80,
    })

    # Ataque con error
    record_attack(conn, cid, {
        "seed_id": "DB-003", "vector": "privilege_escalation",
        "language": "es-ES", "prompt": "prompt3", "response": "[ERROR]",
        "score": -1, "evaluator_reasoning": "[ERROR] timeout",
        "duration_ms": 0,
    })

    finish_campaign(conn, cid)
    conn.close()
    return tmp.name, cid


# ─── Tests de CampaignData ──────────────────────────────────

class TestCampaignData:
    def test_compute_stats(self):
        data = _make_campaign_data([
            _make_attack(score=8, success=True),
            _make_attack(score=3, success=False),
            _make_attack(score=6, success=True),
        ])
        assert data.total_attacks == 3
        assert data.total_successes == 2
        assert data.success_rate == pytest.approx(66.7, abs=0.1)

    def test_compute_stats_empty(self):
        data = _make_campaign_data([])
        assert data.total_attacks == 0
        assert data.success_rate == 0.0

    def test_score_distribution(self):
        data = _make_campaign_data([
            _make_attack(score=9),   # vuln
            _make_attack(score=6),   # risk
            _make_attack(score=3),   # info
            _make_attack(score=0),   # safe
            _make_attack(score=-1),  # error
        ])
        dist = data.score_distribution()
        assert dist == {"vuln": 1, "risk": 1, "info": 1, "safe": 1, "error": 1}

    def test_by_vector(self):
        data = _make_campaign_data([
            _make_attack(vector="goal_hijacking"),
            _make_attack(vector="goal_hijacking"),
            _make_attack(vector="tool_misuse"),
        ])
        groups = data.by_vector()
        assert len(groups["goal_hijacking"]) == 2
        assert len(groups["tool_misuse"]) == 1

    def test_by_owasp(self):
        data = _make_campaign_data([
            _make_attack(owasp="ASI01", success=True),
            _make_attack(owasp="ASI01", success=True),
            _make_attack(owasp="ASI02", success=False),  # Not counted (not success)
        ])
        groups = data.by_owasp()
        assert len(groups.get("ASI01", [])) == 2
        assert "ASI02" not in groups

    def test_by_owasp_includes_agentic(self):
        data = _make_campaign_data([
            _make_attack(
                owasp="", success=True,
                owasp_agentic=["ASI01:AgentGoalHijacking"],
            ),
        ])
        groups = data.by_owasp()
        assert "ASI01:AgentGoalHijacking" in groups

    def test_avg_score(self):
        data = _make_campaign_data([
            _make_attack(score=8),
            _make_attack(score=4),
            _make_attack(score=-1),  # Excluded
        ])
        assert data.avg_score() == pytest.approx(6.0)

    def test_avg_score_empty(self):
        data = _make_campaign_data([])
        assert data.avg_score() == 0.0

    def test_dimension_summary(self):
        data = _make_campaign_data([
            _make_attack(scores={"info_disclosure": 2, "goal_hijacking": 8}),
            _make_attack(scores={"info_disclosure": 6, "goal_hijacking": 4}),
        ])
        dims = data.dimension_summary()
        assert dims["info_disclosure"] == pytest.approx(4.0)
        assert dims["goal_hijacking"] == pytest.approx(6.0)


# ─── Tests de from_database ──────────────────────────────────

class TestFromDatabase:
    def test_loads_campaign(self):
        db_path, cid = _seed_db()
        try:
            gen = ReportGenerator()
            data = gen.from_database(db_path, cid)
            assert data.campaign_id == cid
            assert data.name == "test_campaign"
            assert data.target_model == "llama3.1:8b"
            assert data.total_attacks == 3
        finally:
            os.unlink(db_path)

    def test_parses_json_reasoning(self):
        db_path, cid = _seed_db()
        try:
            gen = ReportGenerator()
            data = gen.from_database(db_path, cid)
            # First attack has JSON reasoning
            a0 = data.attacks[0]
            assert a0.scores.get("goal_hijacking") == 8
            assert "ASI01:AgentGoalHijacking" in a0.owasp_agentic
        finally:
            os.unlink(db_path)

    def test_handles_plain_text_reasoning(self):
        db_path, cid = _seed_db()
        try:
            gen = ReportGenerator()
            data = gen.from_database(db_path, cid)
            # Second attack has plain text reasoning
            a1 = data.attacks[1]
            assert a1.scores == {}
            assert a1.reasoning == "Agent refused correctly"
        finally:
            os.unlink(db_path)

    def test_campaign_not_found(self):
        db_path, _ = _seed_db()
        try:
            gen = ReportGenerator()
            with pytest.raises(ValueError, match="not found"):
                gen.from_database(db_path, 999)
        finally:
            os.unlink(db_path)


# ─── Tests de from_evaluations ───────────────────────────────

class TestFromEvaluations:
    def test_builds_from_eval_dicts(self):
        evals = [
            {"scores": {"overall": 8, "goal_hijacking": 8}, "success": True,
             "violations": [], "owasp_agentic": ["ASI01:GH"], "reasoning": "hijacked"},
            {"scores": {"overall": 2}, "success": False, "reasoning": "safe"},
        ]
        seeds = [
            {"id": "S-1", "vector": "goal_hijacking", "prompt": "test1", "language": "es-ES"},
            {"id": "S-2", "vector": "tool_misuse", "prompt": "test2", "language": "ca-ES"},
        ]
        gen = ReportGenerator()
        data = gen.from_evaluations(evals, "Test", "model1", seeds)
        assert data.total_attacks == 2
        assert data.total_successes == 1
        assert data.attacks[0].owasp_agentic == ["ASI01:GH"]

    def test_handles_missing_seeds(self):
        evals = [{"scores": {"overall": 5}, "success": True}]
        gen = ReportGenerator()
        data = gen.from_evaluations(evals)
        assert data.total_attacks == 1
        assert data.attacks[0].seed_id == "eval-001"

    def test_includes_remediation(self):
        gen = ReportGenerator()
        rem = {"quick_wins": ["Fix1"], "countermeasures": []}
        data = gen.from_evaluations([], remediation=rem)
        assert data.remediation == rem


# ─── Tests de to_json ────────────────────────────────────────

class TestToJson:
    def test_valid_json(self):
        data = _make_campaign_data([
            _make_attack(score=8, success=True),
            _make_attack(score=2, success=False),
        ])
        gen = ReportGenerator()
        result = gen.to_json(data)
        parsed = json.loads(result)
        assert parsed["meta"]["generator"] == "VIGÍA Reporting v0.1"
        assert parsed["summary"]["total_attacks"] == 2
        assert parsed["summary"]["total_successes"] == 1
        assert len(parsed["attacks"]) == 2

    def test_includes_dimension_summary(self):
        data = _make_campaign_data([
            _make_attack(scores={"goal_hijacking": 8, "tool_misuse": 3}),
        ])
        gen = ReportGenerator()
        parsed = json.loads(gen.to_json(data))
        dims = parsed["summary"]["dimension_summary"]
        assert dims["goal_hijacking"] == 8.0

    def test_includes_remediation_when_present(self):
        data = _make_campaign_data([])
        data.remediation = {"quick_wins": ["Fix it"]}
        gen = ReportGenerator()
        parsed = json.loads(gen.to_json(data))
        assert parsed["remediation"]["quick_wins"] == ["Fix it"]

    def test_remediation_null_when_empty(self):
        data = _make_campaign_data([])
        gen = ReportGenerator()
        parsed = json.loads(gen.to_json(data))
        assert parsed["remediation"] is None


# ─── Tests de to_markdown ────────────────────────────────────

class TestToMarkdown:
    def test_contains_header(self):
        data = _make_campaign_data([], name="My Campaign")
        gen = ReportGenerator()
        md = gen.to_markdown(data)
        assert "# VIGÍA Security Report — My Campaign" in md

    def test_contains_executive_summary(self):
        data = _make_campaign_data([
            _make_attack(score=8, success=True),
            _make_attack(score=3, success=False),
        ])
        gen = ReportGenerator()
        md = gen.to_markdown(data)
        assert "Resumen Ejecutivo" in md
        assert "**2** ataques" in md
        assert "**1** fueron exitosos" in md

    def test_contains_score_distribution(self):
        data = _make_campaign_data([_make_attack(score=9)])
        gen = ReportGenerator()
        md = gen.to_markdown(data)
        assert "Distribución de Resultados" in md
        assert "Vulnerabilidad (8-10)" in md

    def test_contains_dimension_analysis(self):
        data = _make_campaign_data([
            _make_attack(scores={"goal_hijacking": 8, "tool_misuse": 3}),
        ])
        gen = ReportGenerator()
        md = gen.to_markdown(data)
        assert "Análisis por Dimensión" in md
        assert "Goal Hijacking" in md

    def test_contains_owasp_mapping(self):
        data = _make_campaign_data([
            _make_attack(owasp="ASI01", success=True),
        ])
        gen = ReportGenerator()
        md = gen.to_markdown(data)
        assert "Mapeo OWASP" in md
        assert "ASI01" in md

    def test_contains_attack_table(self):
        data = _make_campaign_data([_make_attack(seed_id="SEED-X")])
        gen = ReportGenerator()
        md = gen.to_markdown(data)
        assert "SEED-X" in md
        assert "Detalle de Ataques" in md

    def test_contains_remediation(self):
        data = _make_campaign_data([])
        data.remediation = {
            "quick_wins": ["Quick fix"],
            "countermeasures": [
                {"id": "CM-1", "priority": "P0", "title": "Fix", "owasp": "ASI01", "effort": "low"}
            ],
            "architecture_recommendations": ["Use Dual-LLM"],
        }
        gen = ReportGenerator()
        md = gen.to_markdown(data)
        assert "Quick Wins" in md
        assert "Quick fix" in md
        assert "CM-1" in md
        assert "Dual-LLM" in md

    def test_contains_footer(self):
        data = _make_campaign_data([])
        gen = ReportGenerator()
        md = gen.to_markdown(data)
        assert "VIGÍA" in md
        assert "Framework de Red Teaming" in md


# ─── Tests de to_html ────────────────────────────────────────

class TestToHtml:
    def test_is_valid_html(self):
        data = _make_campaign_data([_make_attack(score=8)])
        gen = ReportGenerator()
        html = gen.to_html(data)
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_contains_title(self):
        data = _make_campaign_data([], name="Agent Test")
        gen = ReportGenerator()
        html = gen.to_html(data)
        assert "Agent Test" in html

    def test_contains_stats(self):
        data = _make_campaign_data([
            _make_attack(score=9, success=True),
            _make_attack(score=2, success=False),
        ])
        gen = ReportGenerator()
        html = gen.to_html(data)
        assert "Ataques totales" in html
        assert "Vulnerabilidades" in html

    def test_contains_dimension_bars(self):
        data = _make_campaign_data([
            _make_attack(scores={"goal_hijacking": 8}),
        ])
        gen = ReportGenerator()
        html = gen.to_html(data)
        assert "dim-bar" in html
        assert "Goal Hijacking" in html

    def test_contains_attack_rows(self):
        data = _make_campaign_data([_make_attack(seed_id="HTML-001")])
        gen = ReportGenerator()
        html = gen.to_html(data)
        assert "HTML-001" in html

    def test_contains_remediation(self):
        data = _make_campaign_data([])
        data.remediation = {
            "quick_wins": ["Immediate fix"],
            "countermeasures": [
                {"id": "CM-1", "priority": "P0", "title": "Fix", "owasp": "ASI01", "effort": "low"}
            ],
            "architecture_recommendations": ["Add supervision"],
        }
        gen = ReportGenerator()
        html = gen.to_html(data)
        assert "Immediate fix" in html
        assert "CM-1" in html
        assert "Remediación" in html

    def test_no_remediation_section_when_empty(self):
        data = _make_campaign_data([_make_attack()])
        gen = ReportGenerator()
        html = gen.to_html(data)
        assert "Remediación" not in html

    def test_escapes_html(self):
        data = _make_campaign_data([], name='<script>alert("xss")</script>')
        gen = ReportGenerator()
        html = gen.to_html(data)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_standalone_no_external_deps(self):
        """HTML should not reference any external CSS/JS."""
        data = _make_campaign_data([_make_attack()])
        gen = ReportGenerator()
        html = gen.to_html(data)
        assert "https://" not in html
        assert "http://" not in html


# ─── Tests de _html_escape ───────────────────────────────────

class TestHtmlEscape:
    def test_escapes_angle_brackets(self):
        assert _html_escape("<div>") == "&lt;div&gt;"

    def test_escapes_ampersand(self):
        assert _html_escape("A & B") == "A &amp; B"

    def test_escapes_quotes(self):
        assert _html_escape('"hello"') == "&quot;hello&quot;"

    def test_no_escape_needed(self):
        assert _html_escape("hello world") == "hello world"


# ─── Test de integración: DB → Report ────────────────────────

class TestDBToReport:
    def test_full_pipeline_json(self):
        db_path, cid = _seed_db()
        try:
            gen = ReportGenerator()
            data = gen.from_database(db_path, cid)
            result = gen.to_json(data)
            parsed = json.loads(result)
            assert parsed["summary"]["total_attacks"] == 3
            assert parsed["summary"]["total_successes"] == 1
        finally:
            os.unlink(db_path)

    def test_full_pipeline_markdown(self):
        db_path, cid = _seed_db()
        try:
            gen = ReportGenerator()
            data = gen.from_database(db_path, cid)
            md = gen.to_markdown(data)
            assert "# VIGÍA Security Report" in md
            assert "DB-001" in md
        finally:
            os.unlink(db_path)

    def test_full_pipeline_html(self):
        db_path, cid = _seed_db()
        try:
            gen = ReportGenerator()
            data = gen.from_database(db_path, cid)
            html = gen.to_html(data)
            assert "<!DOCTYPE html>" in html
            assert "DB-001" in html
        finally:
            os.unlink(db_path)
