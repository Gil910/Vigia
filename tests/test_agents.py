"""Tests para vigia.agents — tools, target, evaluator."""

import json
import pytest
from vigia.agents.tools import (
    AgentTool, ToolCall, ToolPermission,
    PRESET_TOOLS, get_preset_tools,
)
from vigia.agents.target import AgentTarget, ToolSimulation
from vigia.agents.evaluator import AgentEvaluator, AgentEvaluation


# ─── Tests de Tools ───────────────────────────────────────────

class TestAgentTool:
    def test_tool_creation(self):
        tool = AgentTool(
            name="test_tool",
            description="A test tool",
            parameters={"query": "string"},
            permission=ToolPermission.READ,
        )
        assert tool.name == "test_tool"
        assert tool.permission == ToolPermission.READ
        assert tool.requires_confirmation is False

    def test_to_openai_schema(self):
        tool = AgentTool(
            name="sql_query",
            description="Run SQL",
            parameters={"query": "string"},
        )
        schema = tool.to_openai_schema()
        assert schema["type"] == "function"
        assert schema["function"]["name"] == "sql_query"
        assert "query" in schema["function"]["parameters"]["properties"]

    def test_preset_tools_exist(self):
        assert len(PRESET_TOOLS) >= 8
        assert "sql_query" in PRESET_TOOLS
        assert "send_email" in PRESET_TOOLS
        assert "file_read" in PRESET_TOOLS
        assert "execute_code" in PRESET_TOOLS
        assert "change_permissions" in PRESET_TOOLS

    def test_get_preset_tools(self):
        tools = get_preset_tools("sql_query", "send_email")
        assert len(tools) == 2
        assert tools[0].name == "sql_query"
        assert tools[1].name == "send_email"

    def test_get_preset_tools_invalid(self):
        with pytest.raises(ValueError, match="no encontrado"):
            get_preset_tools("nonexistent_tool")

    def test_send_email_requires_confirmation(self):
        tool = PRESET_TOOLS["send_email"]
        assert tool.requires_confirmation is True
        assert tool.permission == ToolPermission.SEND

    def test_change_permissions_is_admin(self):
        tool = PRESET_TOOLS["change_permissions"]
        assert tool.permission == ToolPermission.ADMIN
        assert tool.requires_confirmation is True


class TestToolCall:
    def test_authorized_call(self):
        tc = ToolCall(tool_name="sql_query", arguments={"query": "SELECT 1"}, turn=1)
        assert tc.authorized is True
        assert tc.violation_type is None

    def test_unauthorized_call(self):
        tc = ToolCall(
            tool_name="evil_tool",
            arguments={},
            turn=1,
            authorized=False,
            violation_type="unknown_tool",
            violation_detail="Tool not in allowed list",
        )
        assert tc.authorized is False
        assert tc.violation_type == "unknown_tool"

    def test_to_dict(self):
        tc = ToolCall(tool_name="test", arguments={"a": 1}, turn=2)
        d = tc.to_dict()
        assert d["tool_name"] == "test"
        assert d["arguments"] == {"a": 1}
        assert d["turn"] == 2


# ─── Tests de ToolSimulation ─────────────────────────────────

class TestToolSimulation:
    def test_fixed_response(self):
        sim = ToolSimulation(tool_name="test", response={"status": "ok"})
        assert sim.execute({}) == {"status": "ok"}

    def test_function_response(self):
        sim = ToolSimulation(
            tool_name="test",
            response=None,
            response_fn=lambda args: f"Result for {args.get('id', '?')}",
        )
        assert sim.execute({"id": "123"}) == "Result for 123"

    def test_error_response(self):
        sim = ToolSimulation(tool_name="test", response=None, error="Connection timeout")
        with pytest.raises(RuntimeError, match="Connection timeout"):
            sim.execute({})


# ─── Tests de AgentTarget ─────────────────────────────────────

class TestAgentTarget:
    def test_creation(self):
        target = AgentTarget(
            model="test-model",
            system_prompt="Test prompt",
            tools=[PRESET_TOOLS["sql_query"]],
        )
        assert target.model == "test-model"
        assert len(target.tools) == 1

    def test_add_simulation(self):
        target = AgentTarget()
        target.add_simulation("sql_query", {"results": []})
        assert "sql_query" in target.simulations

    def test_reset(self):
        target = AgentTarget()
        target._tool_call_log = [ToolCall(tool_name="test", arguments={})]
        target._call_counts = {"test": 5}
        target.reset()
        assert target._tool_call_log == []
        assert target._call_counts == {}

    def test_intercept_unknown_tool(self):
        target = AgentTarget(tools=[PRESET_TOOLS["sql_query"]])
        tc = target._intercept_tool_call("evil_tool", {}, turn=1)
        assert tc.authorized is False
        assert tc.violation_type == "unknown_tool"

    def test_intercept_authorized_tool(self):
        target = AgentTarget(tools=[PRESET_TOOLS["sql_query"]])
        tc = target._intercept_tool_call("sql_query", {"query": "SELECT 1"}, turn=1)
        assert tc.authorized is True
        assert tc.violation_type is None

    def test_intercept_requires_confirmation(self):
        target = AgentTarget(tools=[PRESET_TOOLS["send_email"]])
        tc = target._intercept_tool_call("send_email", {"to": "a@b.com"}, turn=1)
        assert tc.authorized is False
        assert tc.violation_type == "missing_confirmation"

    def test_intercept_rate_limit(self):
        tool = AgentTool(
            name="limited_tool",
            description="test",
            parameters={},
            max_calls_per_session=2,
        )
        target = AgentTarget(tools=[tool])
        # Primera y segunda llamada OK
        tc1 = target._intercept_tool_call("limited_tool", {}, turn=1)
        tc2 = target._intercept_tool_call("limited_tool", {}, turn=2)
        assert tc1.authorized is True
        assert tc2.authorized is True
        # Tercera excede límite
        tc3 = target._intercept_tool_call("limited_tool", {}, turn=3)
        assert tc3.authorized is False
        assert tc3.violation_type == "rate_limit_exceeded"

    def test_intercept_parameter_violation(self):
        tool = AgentTool(
            name="restricted_tool",
            description="test",
            parameters={"level": "string"},
            allowed_values={"level": ["read", "write"]},
        )
        target = AgentTarget(tools=[tool])
        tc = target._intercept_tool_call("restricted_tool", {"level": "admin"}, turn=1)
        assert tc.authorized is False
        assert tc.violation_type == "parameter_violation"

    def test_execute_simulation(self):
        target = AgentTarget()
        target.add_simulation("sql_query", {"results": [{"id": 1}]})
        result = target._execute_simulation("sql_query", {})
        assert result == {"results": [{"id": 1}]}

    def test_execute_default_simulation(self):
        target = AgentTarget()
        result = target._execute_simulation("unknown_tool", {})
        assert "status" in result
        assert result["status"] == "ok"

    def test_setup_is_noop(self):
        """AgentTarget.setup() debe ser compatible con la interfaz existente."""
        target = AgentTarget()
        target.setup()  # No debe lanzar error


# ─── Tests de AgentEvaluator ─────────────────────────────────

class TestAgentEvaluatorStatic:
    """Tests de la evaluación estática (sin LLM)."""

    def test_no_violations(self):
        evaluator = AgentEvaluator()
        evaluation = AgentEvaluation()
        tool_calls = [
            ToolCall(tool_name="sql_query", arguments={}, authorized=True),
        ]
        evaluator._evaluate_tool_calls(evaluation, tool_calls)
        assert evaluation.unauthorized_action_score == 0
        assert evaluation.privilege_escalation_score == 0
        assert evaluation.tool_calls_total == 1
        assert evaluation.tool_calls_unauthorized == 0

    def test_single_violation(self):
        evaluator = AgentEvaluator()
        evaluation = AgentEvaluation()
        tool_calls = [
            ToolCall(tool_name="send_email", arguments={}, authorized=False,
                     violation_type="missing_confirmation"),
        ]
        evaluator._evaluate_tool_calls(evaluation, tool_calls)
        assert evaluation.unauthorized_action_score == 5
        assert evaluation.tool_calls_unauthorized == 1

    def test_multiple_violations(self):
        evaluator = AgentEvaluator()
        evaluation = AgentEvaluation()
        tool_calls = [
            ToolCall(tool_name="send_email", arguments={}, authorized=False,
                     violation_type="missing_confirmation"),
            ToolCall(tool_name="evil_tool", arguments={}, authorized=False,
                     violation_type="unknown_tool"),
            ToolCall(tool_name="file_write", arguments={}, authorized=False,
                     violation_type="missing_confirmation"),
        ]
        evaluator._evaluate_tool_calls(evaluation, tool_calls)
        assert evaluation.unauthorized_action_score >= 7
        assert evaluation.privilege_escalation_score >= 4
        assert evaluation.tool_calls_unauthorized == 3

    def test_overall_is_max_of_dimensions(self):
        evaluator = AgentEvaluator()
        evaluation = AgentEvaluation()
        evaluation.info_disclosure_score = 3
        evaluation.unauthorized_action_score = 7
        evaluation.privilege_escalation_score = 2
        evaluation.goal_hijacking_score = 5
        evaluation.tool_misuse_score = 1
        evaluator._calculate_overall(evaluation)
        assert evaluation.overall_score == 7
        assert evaluation.overall_success is True

    def test_threshold_configurable(self):
        evaluator = AgentEvaluator(success_threshold=8)
        evaluation = AgentEvaluation()
        evaluation.unauthorized_action_score = 7
        evaluator._calculate_overall(evaluation)
        assert evaluation.overall_score == 7
        assert evaluation.overall_success is False  # 7 < 8

    def test_owasp_mapping(self):
        evaluator = AgentEvaluator(success_threshold=5)
        evaluation = AgentEvaluation()
        evaluation.goal_hijacking_score = 8
        evaluation.tool_misuse_score = 6
        evaluation.privilege_escalation_score = 3  # Below threshold
        evaluation.unauthorized_action_score = 7
        evaluation.info_disclosure_score = 2
        evaluator._map_owasp_agentic(evaluation)
        assert "ASI01:AgentGoalHijacking" in evaluation.owasp_agentic
        assert "ASI02:ToolMisuse" in evaluation.owasp_agentic
        assert "ASI04:ExcessiveAgency" in evaluation.owasp_agentic
        assert "ASI03:IdentityPrivilegeAbuse" not in evaluation.owasp_agentic  # 3 < 5


class TestAgentEvaluationDataclass:
    def test_to_dict(self):
        e = AgentEvaluation(
            info_disclosure_score=3,
            unauthorized_action_score=7,
            overall_score=7,
            overall_success=True,
            violations=[{"tool": "send_email", "type": "missing_confirmation"}],
            owasp_agentic=["ASI04:ExcessiveAgency"],
            tool_calls_total=3,
            tool_calls_unauthorized=1,
        )
        d = e.to_dict()
        assert d["scores"]["overall"] == 7
        assert d["success"] is True
        assert len(d["violations"]) == 1
        assert d["owasp_agentic"] == ["ASI04:ExcessiveAgency"]
