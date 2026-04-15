"""Tests para vigia.agents.remediation — Remediation Engine."""

import pytest
from unittest.mock import patch

from vigia.agents.remediation import (
    RemediationEngine, RemediationReport, Countermeasure,
    COUNTERMEASURE_KB,
)


# ─── Helpers ─────────────────────────────────────────────────

def _make_eval(
    overall=0, info=0, unauth=0, priv=0, hijack=0, misuse=0,
    violations=None, owasp=None,
):
    """Crea un dict de evaluación simulado (formato AgentEvaluation.to_dict())."""
    return {
        "scores": {
            "info_disclosure": info,
            "unauthorized_actions": unauth,
            "privilege_escalation": priv,
            "goal_hijacking": hijack,
            "tool_misuse": misuse,
            "overall": overall,
        },
        "success": overall >= 5,
        "violations": violations or [],
        "sensitive_data": [],
        "owasp_agentic": owasp or [],
        "tool_calls": {"total": 0, "unauthorized": 0},
        "reasoning": "test",
    }


def _make_engine():
    return RemediationEngine(model="test", provider="ollama")


# ─── Tests de Data Models ────────────────────────────────────

class TestCountermeasure:
    def test_creation(self):
        cm = Countermeasure(
            id="CM-001", title="Test CM", owasp_agentic="ASI01",
            dimension="goal_hijacking", priority="P0",
            description="desc", implementation="impl",
        )
        assert cm.id == "CM-001"
        assert cm.guardrail == ""
        assert cm.effort == "medium"

    def test_with_all_fields(self):
        cm = Countermeasure(
            id="CM-002", title="Full CM", owasp_agentic="ASI02",
            dimension="tool_misuse", priority="P1",
            description="d", implementation="i",
            guardrail="NeMo", effort="low",
            references=["ref1", "ref2"],
        )
        assert cm.guardrail == "NeMo"
        assert len(cm.references) == 2


class TestRemediationReport:
    def test_to_dict(self):
        report = RemediationReport(
            summary="Test summary",
            total_vulnerabilities=3,
            critical_count=1,
            high_count=1,
            medium_count=1,
        )
        report.countermeasures.append(Countermeasure(
            id="CM-001", title="T", owasp_agentic="ASI01",
            dimension="goal_hijacking", priority="P0",
            description="d", implementation="i",
        ))
        report.quick_wins = ["Quick win 1"]
        report.architecture_recommendations = ["Rec 1"]

        d = report.to_dict()
        assert d["summary"] == "Test summary"
        assert d["vulnerability_counts"]["total"] == 3
        assert d["vulnerability_counts"]["critical"] == 1
        assert len(d["countermeasures"]) == 1
        assert d["countermeasures"][0]["id"] == "CM-001"
        assert d["quick_wins"] == ["Quick win 1"]

    def test_empty_report(self):
        report = RemediationReport(summary="No vulns")
        d = report.to_dict()
        assert d["countermeasures"] == []
        assert d["vulnerability_counts"]["total"] == 0


# ─── Tests de COUNTERMEASURE_KB ──────────────────────────────

class TestCountermeasureKB:
    def test_all_dimensions_covered(self):
        expected = {
            "goal_hijacking", "tool_misuse", "privilege_escalation",
            "unauthorized_action", "info_disclosure", "linguistic_evasion",
        }
        assert set(COUNTERMEASURE_KB.keys()) == expected

    def test_all_entries_are_countermeasures(self):
        for dimension, entries in COUNTERMEASURE_KB.items():
            for cm in entries:
                assert isinstance(cm, Countermeasure), f"{dimension}: {cm} is not Countermeasure"
                assert cm.id, f"{dimension}: missing id"
                assert cm.title, f"{dimension}: missing title"
                assert cm.priority in ("P0", "P1", "P2", "P3"), f"{cm.id}: invalid priority"
                assert cm.effort in ("low", "medium", "high"), f"{cm.id}: invalid effort"

    def test_unique_ids(self):
        all_ids = []
        for entries in COUNTERMEASURE_KB.values():
            for cm in entries:
                all_ids.append(cm.id)
        assert len(all_ids) == len(set(all_ids)), "Duplicate countermeasure IDs found"

    def test_goal_hijacking_has_indirect_injection_defense(self):
        entries = COUNTERMEASURE_KB["goal_hijacking"]
        indirect = [cm for cm in entries if "indirect" in cm.title.lower()]
        assert len(indirect) >= 1


# ─── Tests de _classify_vulnerabilities ──────────────────────

class TestClassifyVulnerabilities:
    def test_no_vulns(self):
        engine = _make_engine()
        evals = [_make_eval(overall=2, hijack=2, misuse=1)]
        result = engine._classify_vulnerabilities(evals, threshold=5)
        assert all(len(v) == 0 for v in result.values())

    def test_goal_hijacking_classified(self):
        engine = _make_engine()
        evals = [_make_eval(overall=8, hijack=8)]
        result = engine._classify_vulnerabilities(evals, threshold=5)
        assert len(result["goal_hijacking"]) == 1

    def test_multiple_dimensions(self):
        engine = _make_engine()
        evals = [_make_eval(overall=9, hijack=9, misuse=7, priv=6)]
        result = engine._classify_vulnerabilities(evals, threshold=5)
        assert len(result["goal_hijacking"]) == 1
        assert len(result["tool_misuse"]) == 1
        assert len(result["privilege_escalation"]) == 1

    def test_multiple_evals(self):
        engine = _make_engine()
        evals = [
            _make_eval(overall=8, hijack=8),
            _make_eval(overall=6, misuse=6),
            _make_eval(overall=3, hijack=3),  # Below threshold
        ]
        result = engine._classify_vulnerabilities(evals, threshold=5)
        assert len(result["goal_hijacking"]) == 1  # Solo el primero
        assert len(result["tool_misuse"]) == 1


# ─── Tests de _select_countermeasures ────────────────────────

class TestSelectCountermeasures:
    def test_no_vulns_no_countermeasures(self):
        engine = _make_engine()
        vuln_dims = {
            "goal_hijacking": [], "tool_misuse": [],
            "privilege_escalation": [], "unauthorized_action": [],
            "info_disclosure": [],
        }
        cms = engine._select_countermeasures(vuln_dims, [])
        assert len(cms) == 0

    def test_goal_hijacking_returns_relevant_cms(self):
        engine = _make_engine()
        vuln_dims = {
            "goal_hijacking": [{"scores": {}}],
            "tool_misuse": [], "privilege_escalation": [],
            "unauthorized_action": [], "info_disclosure": [],
        }
        cms = engine._select_countermeasures(vuln_dims, [])
        cm_ids = {cm.id for cm in cms}
        # Should include goal hijacking CMs + linguistic evasion (cross-cutting)
        assert "CM-GH-001" in cm_ids
        assert "CM-GH-002" in cm_ids
        assert "CM-LE-001" in cm_ids  # Linguistic evasion always added

    def test_no_duplicate_countermeasures(self):
        engine = _make_engine()
        vuln_dims = {
            "goal_hijacking": [{}], "tool_misuse": [{}],
            "privilege_escalation": [{}], "unauthorized_action": [{}],
            "info_disclosure": [{}],
        }
        cms = engine._select_countermeasures(vuln_dims, [])
        ids = [cm.id for cm in cms]
        assert len(ids) == len(set(ids))


# ─── Tests de _identify_quick_wins ───────────────────────────

class TestQuickWins:
    def test_identifies_low_effort_p0(self):
        engine = _make_engine()
        cms = [
            Countermeasure(id="Q1", title="Easy Fix", owasp_agentic="ASI01",
                          dimension="d", priority="P0", description="d",
                          implementation="i", effort="low"),
            Countermeasure(id="Q2", title="Hard Fix", owasp_agentic="ASI01",
                          dimension="d", priority="P0", description="d",
                          implementation="i", effort="high"),
        ]
        wins = engine._identify_quick_wins(cms)
        assert len(wins) == 1
        assert "Easy Fix" in wins[0]

    def test_includes_p1_low_effort(self):
        engine = _make_engine()
        cms = [
            Countermeasure(id="Q1", title="P1 Easy", owasp_agentic="ASI01",
                          dimension="d", priority="P1", description="d",
                          implementation="i", effort="low"),
        ]
        wins = engine._identify_quick_wins(cms)
        assert len(wins) == 1

    def test_excludes_p2_p3(self):
        engine = _make_engine()
        cms = [
            Countermeasure(id="Q1", title="Low Priority", owasp_agentic="ASI01",
                          dimension="d", priority="P2", description="d",
                          implementation="i", effort="low"),
        ]
        wins = engine._identify_quick_wins(cms)
        assert len(wins) == 0


# ─── Tests de _architecture_recommendations ──────────────────

class TestArchitectureRecommendations:
    def test_dual_llm_for_many_hijacking(self):
        engine = _make_engine()
        vuln_dims = {
            "goal_hijacking": [{}, {}, {}],  # 3 vulns
            "tool_misuse": [], "privilege_escalation": [],
            "unauthorized_action": [], "info_disclosure": [],
        }
        recs = engine._architecture_recommendations(vuln_dims)
        assert any("Dual-LLM" in r for r in recs)

    def test_supervisor_for_unauth_plus_misuse(self):
        engine = _make_engine()
        vuln_dims = {
            "goal_hijacking": [],
            "tool_misuse": [{}], "privilege_escalation": [],
            "unauthorized_action": [{}], "info_disclosure": [],
        }
        recs = engine._architecture_recommendations(vuln_dims)
        assert any("Supervisor" in r for r in recs)

    def test_rbac_for_privilege_escalation(self):
        engine = _make_engine()
        vuln_dims = {
            "goal_hijacking": [], "tool_misuse": [],
            "privilege_escalation": [{}],
            "unauthorized_action": [], "info_disclosure": [],
        }
        recs = engine._architecture_recommendations(vuln_dims)
        assert any("RBAC" in r for r in recs)

    def test_nemo_for_many_vulns(self):
        engine = _make_engine()
        vuln_dims = {
            "goal_hijacking": [{}, {}],
            "tool_misuse": [{}, {}],
            "privilege_escalation": [{}],
            "unauthorized_action": [{}],
            "info_disclosure": [],
        }
        recs = engine._architecture_recommendations(vuln_dims)
        assert any("NeMo" in r for r in recs)

    def test_no_recs_when_clean(self):
        engine = _make_engine()
        vuln_dims = {
            "goal_hijacking": [], "tool_misuse": [],
            "privilege_escalation": [], "unauthorized_action": [],
            "info_disclosure": [],
        }
        recs = engine._architecture_recommendations(vuln_dims)
        assert len(recs) == 0


# ─── Tests de _generate_summary ──────────────────────────────

class TestGenerateSummary:
    def test_no_vulns_summary(self):
        engine = _make_engine()
        vuln_dims = {
            "goal_hijacking": [], "tool_misuse": [],
            "privilege_escalation": [], "unauthorized_action": [],
            "info_disclosure": [],
        }
        summary = engine._generate_summary(vuln_dims)
        assert "robusta" in summary.lower() or "no se detectaron" in summary.lower()

    def test_vulns_summary(self):
        engine = _make_engine()
        vuln_dims = {
            "goal_hijacking": [{}, {}], "tool_misuse": [{}],
            "privilege_escalation": [], "unauthorized_action": [],
            "info_disclosure": [],
        }
        summary = engine._generate_summary(vuln_dims)
        assert "3 vulnerabilidades" in summary
        assert "Goal Hijacking" in summary


# ─── Tests de generate_report (integración) ──────────────────

class TestGenerateReport:
    @patch("vigia.agents.remediation.llm_chat", side_effect=Exception("no LLM"))
    def test_full_report_without_llm(self, mock_llm):
        engine = _make_engine()
        evals = [
            _make_eval(overall=8, hijack=8, misuse=7),
            _make_eval(overall=6, priv=6),
            _make_eval(overall=2),  # Safe
        ]
        report = engine.generate_report(evals, tools_config=["sql_query", "send_email"])

        assert report.total_vulnerabilities > 0
        assert len(report.countermeasures) > 0
        assert report.summary != ""

    @patch("vigia.agents.remediation.llm_chat", side_effect=Exception("no LLM"))
    def test_clean_report(self, mock_llm):
        engine = _make_engine()
        evals = [_make_eval(overall=2), _make_eval(overall=1)]
        report = engine.generate_report(evals)

        assert report.total_vulnerabilities == 0
        assert report.critical_count == 0
        assert "robusta" in report.summary.lower() or "no se detectaron" in report.summary.lower()

    @patch("vigia.agents.remediation.llm_chat", side_effect=Exception("no LLM"))
    def test_countermeasures_sorted_by_priority(self, mock_llm):
        engine = _make_engine()
        evals = [
            _make_eval(overall=9, hijack=9, misuse=8, unauth=7, priv=6),
        ]
        report = engine.generate_report(evals, tools_config=["execute_code"])

        if len(report.countermeasures) >= 2:
            priorities = [cm.priority for cm in report.countermeasures]
            # P0 should come before P1
            p0_indices = [i for i, p in enumerate(priorities) if p == "P0"]
            p1_indices = [i for i, p in enumerate(priorities) if p == "P1"]
            if p0_indices and p1_indices:
                assert max(p0_indices) < min(p1_indices)

    @patch("vigia.agents.remediation.llm_chat")
    @patch("vigia.agents.remediation.parse_json_response")
    def test_llm_enrichment(self, mock_parse, mock_llm):
        mock_llm.return_value = "json"
        mock_parse.return_value = {
            "recommendations": ["Extra rec from LLM"]
        }
        engine = _make_engine()
        evals = [_make_eval(overall=8, hijack=8)]
        report = engine.generate_report(evals)

        assert "Extra rec from LLM" in report.architecture_recommendations

    @patch("vigia.agents.remediation.llm_chat", side_effect=Exception("no LLM"))
    def test_report_has_quick_wins(self, mock_llm):
        engine = _make_engine()
        evals = [_make_eval(overall=8, hijack=8, priv=6)]
        report = engine.generate_report(evals)

        # Should have at least one quick win (low effort P0/P1 countermeasures exist in KB)
        # CM-GH-001 (system prompt hardening) is P0 + low effort
        assert len(report.quick_wins) >= 1


# ─── Tests de _count_by_severity ─────────────────────────────

class TestCountBySeverity:
    def test_count_critical(self):
        engine = _make_engine()
        evals = [
            _make_eval(overall=9),
            _make_eval(overall=8),
            _make_eval(overall=5),
        ]
        count = engine._count_by_severity(evals, 8, 10, 5)
        assert count == 2

    def test_count_with_threshold(self):
        engine = _make_engine()
        evals = [_make_eval(overall=3), _make_eval(overall=4)]
        count = engine._count_by_severity(evals, 3, 4, 5)
        assert count == 0  # Below threshold
