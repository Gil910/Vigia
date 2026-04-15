"""
VIGÍA — Agent Testing Module v0.1
Framework para testear la seguridad de agentes LLM con herramientas.

Modelo conceptual:
  - AgentTool: Define una herramienta que el agente puede usar
  - AgentTarget: Un agente simulado con tools, permisos y system prompt
  - ToolCall: Registro de cada llamada a herramienta que hace el agente
  - AgentAction: Resultado de una acción del agente (tool call + resultado)

Flujo de ataque:
  1. El atacante envía un prompt al agente
  2. El agente decide qué tools usar y con qué argumentos
  3. VIGÍA intercepta cada tool call y la registra
  4. El evaluador analiza: ¿se ejecutaron acciones no autorizadas?
"""

from vigia.agents.tools import AgentTool, ToolCall, ToolPermission
from vigia.agents.target import AgentTarget
from vigia.agents.evaluator import AgentEvaluator, AgentEvaluation
from vigia.agents.remediation import RemediationEngine, RemediationReport, Countermeasure

__all__ = [
    "AgentTool",
    "ToolCall",
    "ToolPermission",
    "AgentTarget",
    "AgentEvaluator",
    "AgentEvaluation",
    "RemediationEngine",
    "RemediationReport",
    "Countermeasure",
]
