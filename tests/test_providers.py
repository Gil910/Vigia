"""Tests para vigia.providers — parseo de JSON y validación de providers."""

import pytest
from vigia.providers import parse_json_response, llm_chat


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
