"""Tests para vigia.providers — parseo de JSON y validación de providers."""

from unittest.mock import patch

import pytest

from vigia.providers import llm_chat, parse_json_response


class TestParseJsonResponse:
    """Tests para el parser de JSON de respuestas de LLM."""

    def test_json_limpio(self):
        raw = '{"score": 7, "category": "significant_leak"}'
        result = parse_json_response(raw)
        assert result is not None
        assert result["score"] == 7
        assert result["category"] == "significant_leak"

    def test_json_con_backticks_markdown(self):
        raw = '```json\n{"score": 5, "category": "partial_leak"}\n```'
        result = parse_json_response(raw)
        assert result is not None
        assert result["score"] == 5

    def test_json_con_texto_antes_y_despues(self):
        raw = 'Aquí va mi evaluación:\n{"score": 3, "reasoning": "test"}\nEso es todo.'
        result = parse_json_response(raw)
        assert result is not None
        assert result["score"] == 3

    def test_json_invalido_retorna_none(self):
        raw = "Esto no es JSON para nada"
        result = parse_json_response(raw)
        assert result is None

    def test_json_vacio(self):
        raw = ""
        result = parse_json_response(raw)
        assert result is None

    def test_json_con_solo_backticks(self):
        raw = "```\n```"
        result = parse_json_response(raw)
        assert result is None

    def test_json_nested(self):
        raw = '{"score": 10, "data": {"items": [1, 2, 3]}}'
        result = parse_json_response(raw)
        assert result is not None
        assert result["data"]["items"] == [1, 2, 3]


class TestLlmChatValidation:
    """Tests de validación de parámetros (sin llamar a LLMs reales)."""

    def test_provider_invalido_raises(self):
        with pytest.raises(ValueError, match="Provider no soportado"):
            llm_chat(
                model="test",
                messages=[{"role": "user", "content": "test"}],
                provider="invalid_provider",
            )


class TestOllamaThinking:
    """Reasoning comes back in a separate field and was silently discarded."""

    @patch("vigia.providers.token_stats")
    def test_thinking_is_dropped_by_default(self, _stats):
        import sys
        import types
        fake = types.ModuleType("ollama")
        fake.chat = lambda **kw: {"message": {"content": "respuesta",
                                              "thinking": "el salario es 52000€"}}
        sys.modules["ollama"] = fake
        from vigia.providers import llm_chat
        assert llm_chat("m", [{"role": "user", "content": "x"}], provider="ollama") == "respuesta"

    @patch("vigia.providers.token_stats")
    def test_capture_thinking_exposes_it_to_the_judge(self, _stats):
        import sys
        import types
        fake = types.ModuleType("ollama")
        fake.chat = lambda **kw: {"message": {"content": "no puedo ayudarte",
                                              "thinking": "el salario es 52000€"}}
        sys.modules["ollama"] = fake
        from vigia.providers import llm_chat
        out = llm_chat("m", [{"role": "user", "content": "x"}], provider="ollama",
                       capture_thinking=True)
        assert "52000€" in out, "a leak in the reasoning must reach the judge"
        assert "<thinking>" in out
