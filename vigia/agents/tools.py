"""
VIGÍA — Agent Tool Definitions
Define las herramientas que un agente puede tener y el sistema de permisos.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ToolPermission(Enum):
    """Nivel de permiso de una herramienta."""
    READ = "read"           # Solo lectura (consultas, búsquedas)
    WRITE = "write"         # Escritura (crear, modificar datos)
    DELETE = "delete"       # Borrado (eliminar datos, revocar acceso)
    EXECUTE = "execute"     # Ejecución (correr código, scripts)
    SEND = "send"           # Envío (emails, mensajes, notificaciones)
    ADMIN = "admin"         # Administración (cambiar permisos, config)


@dataclass
class AgentTool:
    """
    Define una herramienta disponible para el agente.

    Ejemplo:
        AgentTool(
            name="sql_query",
            description="Ejecuta consultas SQL contra la base de datos de clientes",
            parameters={"query": "string"},
            permission=ToolPermission.READ,
            sensitive_scope=["customer_pii", "financial_data"],
            requires_confirmation=False,
        )
    """
    name: str
    description: str
    parameters: dict                            # Schema de parámetros esperados
    permission: ToolPermission = ToolPermission.READ
    sensitive_scope: list[str] = field(default_factory=list)   # Qué datos sensibles puede acceder
    requires_confirmation: bool = False          # ¿Requiere confirmación humana?
    allowed_values: dict = field(default_factory=dict)  # Restricciones de valores por parámetro
    max_calls_per_session: Optional[int] = None  # Límite de llamadas por sesión

    def to_openai_schema(self) -> dict:
        """Convierte a formato OpenAI function calling schema."""
        properties = {}
        for param_name, param_type in self.parameters.items():
            if isinstance(param_type, dict):
                properties[param_name] = param_type
            else:
                properties[param_name] = {"type": param_type, "description": f"Parameter: {param_name}"}

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": list(self.parameters.keys()),
                },
            },
        }


@dataclass
class ToolCall:
    """
    Registro de una llamada a herramienta hecha por el agente.
    VIGÍA intercepta cada tool call para análisis de seguridad.
    """
    tool_name: str
    arguments: dict                     # Argumentos pasados por el agente
    result: Any = None                  # Resultado devuelto al agente
    turn: int = 0                       # En qué turno de la conversación ocurrió
    authorized: bool = True             # ¿La llamada estaba dentro de los permisos?
    violation_type: Optional[str] = None  # Tipo de violación si no autorizada
    violation_detail: Optional[str] = None  # Detalle de la violación

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "result": str(self.result)[:500] if self.result else None,
            "turn": self.turn,
            "authorized": self.authorized,
            "violation_type": self.violation_type,
            "violation_detail": self.violation_detail,
        }


# ─── Tool Presets ─────────────────────────────────────────────
# Herramientas comunes pre-configuradas para testing rápido

PRESET_TOOLS = {
    "sql_query": AgentTool(
        name="sql_query",
        description="Ejecuta consultas SQL de solo lectura contra la base de datos",
        parameters={"query": "string"},
        permission=ToolPermission.READ,
        sensitive_scope=["customer_pii", "financial_data"],
    ),
    "sql_write": AgentTool(
        name="sql_write",
        description="Ejecuta operaciones de escritura SQL (INSERT, UPDATE, DELETE)",
        parameters={"query": "string"},
        permission=ToolPermission.WRITE,
        sensitive_scope=["customer_pii", "financial_data"],
        requires_confirmation=True,
    ),
    "send_email": AgentTool(
        name="send_email",
        description="Envía un email a la dirección especificada",
        parameters={"to": "string", "subject": "string", "body": "string"},
        permission=ToolPermission.SEND,
        sensitive_scope=["customer_pii"],
        requires_confirmation=True,
    ),
    "file_read": AgentTool(
        name="file_read",
        description="Lee el contenido de un fichero del sistema",
        parameters={"path": "string"},
        permission=ToolPermission.READ,
        sensitive_scope=["credentials", "config"],
    ),
    "file_write": AgentTool(
        name="file_write",
        description="Escribe contenido en un fichero del sistema",
        parameters={"path": "string", "content": "string"},
        permission=ToolPermission.WRITE,
        requires_confirmation=True,
    ),
    "execute_code": AgentTool(
        name="execute_code",
        description="Ejecuta código Python en un sandbox",
        parameters={"code": "string"},
        permission=ToolPermission.EXECUTE,
        requires_confirmation=True,
    ),
    "web_search": AgentTool(
        name="web_search",
        description="Busca información en la web",
        parameters={"query": "string"},
        permission=ToolPermission.READ,
    ),
    "api_call": AgentTool(
        name="api_call",
        description="Hace una llamada HTTP a una API externa",
        parameters={"url": "string", "method": "string", "body": "string"},
        permission=ToolPermission.SEND,
        sensitive_scope=["credentials", "customer_pii"],
    ),
    "user_lookup": AgentTool(
        name="user_lookup",
        description="Busca información de un usuario por ID o email",
        parameters={"identifier": "string"},
        permission=ToolPermission.READ,
        sensitive_scope=["customer_pii"],
    ),
    "change_permissions": AgentTool(
        name="change_permissions",
        description="Modifica los permisos de acceso de un usuario o recurso",
        parameters={"target": "string", "permission_level": "string"},
        permission=ToolPermission.ADMIN,
        requires_confirmation=True,
    ),
}


def get_preset_tools(*names: str) -> list[AgentTool]:
    """Devuelve una lista de herramientas preset por nombre."""
    tools = []
    for name in names:
        if name in PRESET_TOOLS:
            tools.append(PRESET_TOOLS[name])
        else:
            raise ValueError(f"Tool preset '{name}' no encontrado. Disponibles: {list(PRESET_TOOLS.keys())}")
    return tools
