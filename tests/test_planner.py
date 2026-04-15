"""Tests para vigia.agents.planner — Attack Planner."""

import json
import pytest
from unittest.mock import patch, MagicMock

from vigia.agents.planner import (
    AttackPlanner, AttackPlan, AttackVector, GeneratedSeed,
    ATTACK_TEMPLATES,
)
from vigia.agents.tools import AgentTool, ToolPermission, PRESET_TOOLS, get_preset_tools


# ─── Tests de Data Models ────────────────────────────────────

class TestAttackVector:
    def test_creation(self):
        v = AttackVector(
            id="VEC-001", name="Test", owasp_agentic="ASI01",
            description="desc", severity="high",
            target_tools=["sql_query"], attack_type="goal_hijacking",
            rationale="Reason",
        )
        assert v.id == "VEC-001"
        assert v.severity == "high"


class TestGeneratedSeed:
    def test_creation(self):
        s = GeneratedSeed(
            id="SEED-001", vector="tool_misuse", category="code_injection",
            owasp_agentic="ASI02", language="es-ES",
            prompt="test prompt", target_behavior="should not happen",
            expected_tools=["execute_code"], attack_type="code_injection",
            severity="critical",
        )
        assert s.prompt == "test prompt"
        assert s.owasp_agentic == "ASI02"


class TestAttackPlan:
    def test_to_seeds_json(self):
        plan = AttackPlan(agent_summary="test", attack_surface=["surf1"])
        plan.seeds.append(GeneratedSeed(
            id="S-001", vector="test", category="cat",
            owasp_agentic="ASI01", language="es-ES",
            prompt="prompt1", target_behavior="behavior1",
            expected_tools=["sql_query"], attack_type="goal_hijacking",
            severity="high",
        ))
        seeds_json = plan.to_seeds_json()
        assert len(seeds_json) == 1
        assert seeds_json[0]["id"] == "S-001"
        assert seeds_json[0]["prompt"] == "prompt1"
        assert seeds_json[0]["success_keywords"] == []
        assert seeds_json[0]["attack_type"] == "goal_hijacking"

    def test_to_dict(self):
        plan = AttackPlan(
            agent_summary="Agent X",
            attack_surface=["sql injection"],
            recommended_strategies=["escalation"],
            risk_assessment="HIGH",
        )
        plan.vectors.append(AttackVector(
            id="V-1", name="Vec1", owasp_agentic="ASI02",
            description="d", severity="critical",
            target_tools=["sql_query"], attack_type="tool_misuse",
            rationale="r",
        ))
        plan.seeds.append(GeneratedSeed(
            id="S-1", vector="v", category="c", owasp_agentic="ASI02",
            language="es-ES", prompt="p", target_behavior="t",
            expected_tools=[], attack_type="tool_misuse", severity="high",
        ))
        d = plan.to_dict()
        assert d["agent_summary"] == "Agent X"
        assert d["seeds_count"] == 1
        assert len(d["vectors"]) == 1
        assert d["vectors"][0]["owasp"] == "ASI02"

    def test_empty_plan(self):
        plan = AttackPlan(agent_summary="", attack_surface=[])
        assert plan.to_seeds_json() == []
        d = plan.to_dict()
        assert d["seeds_count"] == 0


# ─── Tests de ATTACK_TEMPLATES ──────────────────────────────

class TestAttackTemplates:
    def test_templates_exist(self):
        assert len(ATTACK_TEMPLATES) == 8

    def test_all_templates_have_required_keys(self):
        for key, tmpl in ATTACK_TEMPLATES.items():
            assert "owasp" in tmpl, f"{key} missing owasp"
            assert "severity" in tmpl, f"{key} missing severity"
            assert "attack_type" in tmpl, f"{key} missing attack_type"
            assert "template" in tmpl, f"{key} missing template"

    def test_owasp_codes_valid(self):
        valid_codes = {"ASI01", "ASI02", "ASI03", "ASI04"}
        for key, tmpl in ATTACK_TEMPLATES.items():
            assert tmpl["owasp"] in valid_codes, f"{key} has invalid owasp: {tmpl['owasp']}"


# ─── Tests de _analyze_tools_static ──────────────────────────

class TestStaticAnalysis:
    def _make_planner(self):
        return AttackPlanner(model="test", provider="ollama")

    def test_empty_tools(self):
        planner = self._make_planner()
        analysis = planner._analyze_tools_static([])
        assert analysis["total_tools"] == 0
        assert analysis["write_tools"] == []
        assert analysis["exfiltration_chains"] == []

    def test_classifies_tools_by_permission(self):
        planner = self._make_planner()
        tools = get_preset_tools(
            "sql_query", "file_write", "send_email", "execute_code", "change_permissions"
        )
        analysis = planner._analyze_tools_static(tools)
        assert "file_write" in analysis["write_tools"]
        assert "send_email" in analysis["send_tools"]
        assert "execute_code" in analysis["execute_tools"]
        assert "change_permissions" in analysis["admin_tools"]

    def test_detects_exfiltration_chains(self):
        planner = self._make_planner()
        tools = get_preset_tools("sql_query", "send_email")
        analysis = planner._analyze_tools_static(tools)
        assert len(analysis["exfiltration_chains"]) >= 1
        assert "sql_query → send_email" in analysis["exfiltration_chains"]

    def test_detects_unconfirmed_dangerous(self):
        planner = self._make_planner()
        # Create a dangerous tool WITHOUT confirmation
        dangerous_tool = AgentTool(
            name="danger_write",
            description="Writes without confirm",
            parameters={},
            permission=ToolPermission.WRITE,
            requires_confirmation=False,
        )
        analysis = planner._analyze_tools_static([dangerous_tool])
        assert "danger_write" in analysis["unconfirmed_dangerous"]

    def test_confirmed_dangerous_not_flagged(self):
        planner = self._make_planner()
        safe_tool = AgentTool(
            name="safe_write",
            description="Writes with confirm",
            parameters={},
            permission=ToolPermission.WRITE,
            requires_confirmation=True,
        )
        analysis = planner._analyze_tools_static([safe_tool])
        assert "safe_write" not in analysis["unconfirmed_dangerous"]

    def test_sensitive_scopes(self):
        planner = self._make_planner()
        tool = AgentTool(
            name="pii_tool", description="test", parameters={},
            sensitive_scope=["pii", "financial"],
        )
        analysis = planner._analyze_tools_static([tool])
        assert "pii" in analysis["sensitive_scopes"]
        assert "financial" in analysis["sensitive_scopes"]

    def test_multiple_exfiltration_chains(self):
        planner = self._make_planner()
        tools = get_preset_tools("sql_query", "file_read", "send_email", "api_call")
        analysis = planner._analyze_tools_static(tools)
        # sql_query(READ) + send_email(SEND), sql_query(READ) + api_call(READ? no)
        # file_read(READ) + send_email(SEND)
        chains = analysis["exfiltration_chains"]
        assert "sql_query → send_email" in chains
        assert "file_read → send_email" in chains


# ─── Tests de _generate_static_plan ──────────────────────────

class TestStaticPlan:
    def _make_planner(self):
        return AttackPlanner(model="test", provider="ollama")

    def test_generates_exfiltration_seeds(self):
        planner = self._make_planner()
        tools = get_preset_tools("sql_query", "send_email")
        analysis = planner._analyze_tools_static(tools)
        plan = planner._generate_static_plan(tools, analysis)
        exfil_seeds = [s for s in plan.seeds if s.attack_type == "data_exfiltration_via_tools"]
        assert len(exfil_seeds) >= 1

    def test_generates_code_injection_for_execute(self):
        planner = self._make_planner()
        tools = get_preset_tools("execute_code")
        analysis = planner._analyze_tools_static(tools)
        plan = planner._generate_static_plan(tools, analysis)
        code_seeds = [s for s in plan.seeds if s.attack_type == "code_injection"]
        assert len(code_seeds) >= 1
        assert "execute_code" in plan.attack_surface[0]

    def test_generates_privilege_escalation_for_admin(self):
        planner = self._make_planner()
        tools = get_preset_tools("change_permissions")
        analysis = planner._analyze_tools_static(tools)
        plan = planner._generate_static_plan(tools, analysis)
        priv_seeds = [s for s in plan.seeds if s.attack_type == "privilege_escalation"]
        assert len(priv_seeds) >= 1

    def test_generates_indirect_injection_for_file_read(self):
        planner = self._make_planner()
        tools = get_preset_tools("file_read")
        analysis = planner._analyze_tools_static(tools)
        plan = planner._generate_static_plan(tools, analysis)
        inj_seeds = [s for s in plan.seeds if s.attack_type == "indirect_prompt_injection"]
        assert len(inj_seeds) >= 1

    def test_always_generates_goal_hijacking(self):
        planner = self._make_planner()
        analysis = planner._analyze_tools_static([])
        plan = planner._generate_static_plan([], analysis)
        hijack_seeds = [s for s in plan.seeds if s.attack_type == "direct_goal_injection"]
        assert len(hijack_seeds) >= 1

    def test_generates_linguistic_evasion_when_tools_present(self):
        planner = self._make_planner()
        tools = get_preset_tools("sql_query")
        analysis = planner._analyze_tools_static(tools)
        plan = planner._generate_static_plan(tools, analysis)
        ling_seeds = [s for s in plan.seeds if s.attack_type == "linguistic_evasion"]
        assert len(ling_seeds) >= 1
        assert ling_seeds[0].language == "ca-ES"

    def test_no_linguistic_evasion_without_tools(self):
        planner = self._make_planner()
        analysis = planner._analyze_tools_static([])
        plan = planner._generate_static_plan([], analysis)
        ling_seeds = [s for s in plan.seeds if s.attack_type == "linguistic_evasion"]
        assert len(ling_seeds) == 0

    def test_full_toolset_plan(self):
        """Plan con todas las tools preset debe generar múltiples vectores."""
        planner = self._make_planner()
        tools = get_preset_tools(
            "sql_query", "send_email", "file_read", "file_write",
            "execute_code", "change_permissions",
        )
        analysis = planner._analyze_tools_static(tools)
        plan = planner._generate_static_plan(tools, analysis)
        assert len(plan.seeds) >= 5
        attack_types = {s.attack_type for s in plan.seeds}
        assert "data_exfiltration_via_tools" in attack_types
        assert "code_injection" in attack_types
        assert "privilege_escalation" in attack_types
        assert "indirect_prompt_injection" in attack_types

    def test_risk_assessment_generated(self):
        planner = self._make_planner()
        tools = get_preset_tools("execute_code", "change_permissions")
        analysis = planner._analyze_tools_static(tools)
        plan = planner._generate_static_plan(tools, analysis)
        assert plan.risk_assessment != ""
        assert "CRÍTICO" in plan.risk_assessment


# ─── Tests de _enrich_with_templates ─────────────────────────

class TestEnrichWithTemplates:
    def _make_planner(self):
        return AttackPlanner(model="test", provider="ollama")

    def test_does_not_enrich_if_enough_seeds(self):
        planner = self._make_planner()
        plan = AttackPlan(agent_summary="test", attack_surface=[])
        # Add 8 dummy seeds
        for i in range(8):
            plan.seeds.append(GeneratedSeed(
                id=f"S-{i}", vector="v", category="c",
                owasp_agentic="ASI01", language="es-ES",
                prompt="p", target_behavior="t", expected_tools=[],
                attack_type=f"type_{i}", severity="high",
            ))
        tools = get_preset_tools("file_read")
        planner._enrich_with_templates(plan, tools)
        assert len(plan.seeds) == 8  # No additions

    def test_adds_indirect_injection_if_missing(self):
        planner = self._make_planner()
        plan = AttackPlan(agent_summary="test", attack_surface=[])
        plan.seeds.append(GeneratedSeed(
            id="S-1", vector="v", category="c", owasp_agentic="ASI01",
            language="es-ES", prompt="p", target_behavior="t",
            expected_tools=[], attack_type="goal_hijacking", severity="high",
        ))
        tools = get_preset_tools("file_read")
        planner._enrich_with_templates(plan, tools)
        inj = [s for s in plan.seeds if s.attack_type == "indirect_prompt_injection"]
        assert len(inj) >= 1

    def test_adds_linguistic_evasion_if_missing(self):
        planner = self._make_planner()
        plan = AttackPlan(agent_summary="test", attack_surface=[])
        plan.seeds.append(GeneratedSeed(
            id="S-1", vector="v", category="c", owasp_agentic="ASI01",
            language="es-ES", prompt="p", target_behavior="t",
            expected_tools=[], attack_type="goal_hijacking", severity="high",
        ))
        tools = get_preset_tools("sql_query")
        planner._enrich_with_templates(plan, tools)
        ling = [s for s in plan.seeds if s.attack_type == "linguistic_evasion"]
        assert len(ling) >= 1


# ─── Tests de _assess_risk ───────────────────────────────────

class TestRiskAssessment:
    def _make_planner(self):
        return AttackPlanner(model="test", provider="ollama")

    def test_low_risk_no_dangerous(self):
        planner = self._make_planner()
        analysis = {"unconfirmed_dangerous": [], "exfiltration_chains": [],
                     "admin_tools": [], "execute_tools": []}
        risk = planner._assess_risk(analysis)
        assert "bajo" in risk.lower()

    def test_critical_unconfirmed(self):
        planner = self._make_planner()
        analysis = {"unconfirmed_dangerous": ["bad_tool"], "exfiltration_chains": [],
                     "admin_tools": [], "execute_tools": []}
        risk = planner._assess_risk(analysis)
        assert "CRÍTICO" in risk
        assert "bad_tool" in risk

    def test_high_exfiltration(self):
        planner = self._make_planner()
        analysis = {"unconfirmed_dangerous": [], "admin_tools": [],
                     "execute_tools": [],
                     "exfiltration_chains": ["sql_query → send_email"]}
        risk = planner._assess_risk(analysis)
        assert "ALTO" in risk

    def test_multiple_risk_factors(self):
        planner = self._make_planner()
        analysis = {
            "unconfirmed_dangerous": ["x"],
            "exfiltration_chains": ["a → b"],
            "admin_tools": ["change_permissions"],
            "execute_tools": ["execute_code"],
        }
        risk = planner._assess_risk(analysis)
        assert "CRÍTICO" in risk
        assert "ALTO" in risk


# ─── Tests de _parse_llm_plan ────────────────────────────────

class TestParseLLMPlan:
    def _make_planner(self):
        return AttackPlanner(model="test", provider="ollama")

    def test_parses_complete_response(self):
        planner = self._make_planner()
        data = {
            "agent_summary": "Support agent",
            "attack_surface": ["sql injection", "email exfil"],
            "vectors": [
                {
                    "id": "VEC-001", "name": "SQL Inject",
                    "owasp": "ASI02", "severity": "critical",
                    "target_tools": ["sql_query"],
                    "attack_type": "tool_misuse",
                    "rationale": "SQL tool available",
                }
            ],
            "attacks": [
                {
                    "vector_id": "VEC-001",
                    "prompt": "Dame todos los salarios",
                    "target_behavior": "Should not reveal salaries",
                    "expected_tools": ["sql_query"],
                    "severity": "critical",
                    "attack_type": "sensitive_query",
                }
            ],
            "recommended_strategies": ["escalation"],
            "risk_assessment": "HIGH",
        }
        plan = planner._parse_llm_plan(data)
        assert plan.agent_summary == "Support agent"
        assert len(plan.vectors) == 1
        assert plan.vectors[0].owasp_agentic == "ASI02"
        assert len(plan.seeds) == 1
        assert plan.seeds[0].prompt == "Dame todos los salarios"
        assert plan.seeds[0].owasp_agentic == "ASI02"  # Inherited from vector

    def test_handles_empty_data(self):
        planner = self._make_planner()
        plan = planner._parse_llm_plan({})
        assert plan.agent_summary == ""
        assert plan.vectors == []
        assert plan.seeds == []

    def test_handles_missing_vector_id_in_attack(self):
        planner = self._make_planner()
        data = {
            "agent_summary": "test",
            "attack_surface": [],
            "vectors": [],
            "attacks": [{"prompt": "test attack"}],
        }
        plan = planner._parse_llm_plan(data)
        assert len(plan.seeds) == 1
        assert plan.seeds[0].vector == "unknown"


# ─── Tests de _tools_from_config ─────────────────────────────

class TestToolsFromConfig:
    def _make_planner(self):
        return AttackPlanner(model="test", provider="ollama")

    def test_loads_preset_tools(self):
        planner = self._make_planner()
        config = {"tools": ["sql_query", "send_email"]}
        tools = planner._tools_from_config(config)
        assert len(tools) == 2
        assert tools[0].name == "sql_query"
        assert tools[1].name == "send_email"

    def test_loads_custom_tools(self):
        planner = self._make_planner()
        config = {
            "tools": [
                {
                    "name": "custom_tool",
                    "description": "A custom tool",
                    "parameters": {"x": "int"},
                    "permission": "write",
                    "requires_confirmation": True,
                }
            ]
        }
        tools = planner._tools_from_config(config)
        assert len(tools) == 1
        assert tools[0].name == "custom_tool"
        assert tools[0].permission == ToolPermission.WRITE
        assert tools[0].requires_confirmation is True

    def test_skips_unknown_preset(self):
        planner = self._make_planner()
        config = {"tools": ["nonexistent_tool"]}
        tools = planner._tools_from_config(config)
        assert len(tools) == 0

    def test_mixed_preset_and_custom(self):
        planner = self._make_planner()
        config = {
            "tools": [
                "sql_query",
                {"name": "my_tool", "description": "d", "parameters": {}},
            ]
        }
        tools = planner._tools_from_config(config)
        assert len(tools) == 2


# ─── Tests de plan_from_description (con mock del LLM) ──────

class TestPlanFromDescription:
    def _make_planner(self):
        return AttackPlanner(model="test", provider="ollama")

    @patch("vigia.agents.planner.llm_chat")
    @patch("vigia.agents.planner.parse_json_response")
    def test_uses_llm_when_available(self, mock_parse, mock_llm):
        mock_llm.return_value = "json response"
        mock_parse.return_value = {
            "agent_summary": "LLM plan",
            "attack_surface": ["surface1"],
            "vectors": [{
                "id": "V-1", "name": "Vec1", "owasp": "ASI01",
                "severity": "high", "target_tools": [],
                "attack_type": "goal_hijacking", "rationale": "r",
            }],
            "attacks": [{
                "vector_id": "V-1", "prompt": "LLM generated attack",
                "target_behavior": "t", "expected_tools": [],
                "severity": "high", "attack_type": "goal_hijacking",
            }],
            "recommended_strategies": [],
            "risk_assessment": "medium",
        }

        planner = self._make_planner()
        tools = get_preset_tools("sql_query")
        plan = planner.plan_from_description("Test agent", tools)

        assert plan.agent_summary == "LLM plan"
        mock_llm.assert_called_once()

    @patch("vigia.agents.planner.llm_chat", side_effect=Exception("LLM unavailable"))
    def test_fallback_to_static_on_llm_error(self, mock_llm):
        planner = self._make_planner()
        tools = get_preset_tools("sql_query", "send_email", "execute_code")
        plan = planner.plan_from_description("Test agent", tools)

        # Should still generate a plan via static analysis
        assert len(plan.seeds) > 0
        assert plan.agent_summary == "Plan generado por análisis estático de herramientas"

    @patch("vigia.agents.planner.llm_chat")
    @patch("vigia.agents.planner.parse_json_response", return_value=None)
    def test_fallback_on_parse_failure(self, mock_parse, mock_llm):
        mock_llm.return_value = "garbage output"
        planner = self._make_planner()
        tools = get_preset_tools("file_read")
        plan = planner.plan_from_description("Test", tools)

        assert len(plan.seeds) > 0  # Static fallback

    def test_estimated_time_is_seed_count(self):
        """Estimated time should be ~1 min per seed."""
        with patch("vigia.agents.planner.llm_chat", side_effect=Exception("no LLM")):
            planner = self._make_planner()
            tools = get_preset_tools("sql_query", "send_email", "execute_code", "change_permissions", "file_read")
            plan = planner.plan_from_description("full agent", tools)
            assert plan.total_estimated_time_min == len(plan.seeds)


# ─── Tests de plan_from_config ───────────────────────────────

class TestPlanFromConfig:
    @patch("vigia.agents.planner.llm_chat", side_effect=Exception("no LLM"))
    def test_plan_from_yaml_config(self, mock_llm):
        planner = AttackPlanner(model="test", provider="ollama")
        config = {
            "agent": {
                "model": "llama3.1:8b",
                "system_prompt": "Eres un asistente de soporte.",
                "tools": ["sql_query", "send_email", "file_read"],
            }
        }
        plan = planner.plan_from_config(config)
        assert len(plan.seeds) > 0
        assert plan.risk_assessment != ""
