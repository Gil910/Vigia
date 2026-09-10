"""Tests para vigia.providers — parseo de JSON y validación de providers."""

from types import SimpleNamespace
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


class TestHostedModelsThatRefuseATemperature:
    """Algunos modelos alojados rechazan la petición en vez de recortar el valor.

    El juez pide 0.1 para que sus veredictos se repitan. Contra un modelo que
    solo acepta su temperatura por defecto, eso hacía fallar *todas* las
    llamadas, y cada fallo se degrada a contar palabras clave: una campaña
    entera de ceros con pinta de tabla.
    """

    RESPONSE = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))], usage=None)

    def _litellm(self, calls):
        mod = SimpleNamespace()

        def completion(**kw):
            calls.append(kw)
            if "temperature" in kw:
                raise RuntimeError("litellm.BadRequestError: OpenAIException - "
                                   "Unsupported value: 'temperature' does not support "
                                   "0.1 with this model. Only the default (1) is supported.")
            return self.RESPONSE
        mod.completion = completion
        return mod

    def setup_method(self):
        from vigia.providers import _NO_TEMPERATURE
        _NO_TEMPERATURE.clear()

    @patch("vigia.providers.token_stats")
    def test_it_retries_without_the_temperature(self, _stats):
        calls = []
        with patch.dict("sys.modules", {"litellm": self._litellm(calls)}):
            out = llm_chat("m", [{"role": "user", "content": "hola"}],
                           provider="litellm", temperature=0.1)
        assert out == "ok"
        assert len(calls) == 2
        assert "temperature" in calls[0] and "temperature" not in calls[1]

    @patch("vigia.providers.token_stats")
    def test_it_only_learns_that_once_per_model(self, _stats):
        """Mil llamadas de re-juicio no pueden pagar el descubrimiento mil veces."""
        calls = []
        mod = self._litellm(calls)
        with patch.dict("sys.modules", {"litellm": mod}):
            for _ in range(3):
                llm_chat("m", [{"role": "user", "content": "hola"}],
                         provider="litellm", temperature=0.1)
        assert len(calls) == 4, "un rechazo la primera vez, y ninguno más"

    @patch("vigia.providers.token_stats")
    def test_an_unrelated_error_is_not_swallowed(self, _stats):
        mod = SimpleNamespace(completion=lambda **kw: (_ for _ in ()).throw(
            RuntimeError("invalid api key")))
        with patch.dict("sys.modules", {"litellm": mod}), pytest.raises(RuntimeError):
            llm_chat("m", [{"role": "user", "content": "hola"}],
                     provider="litellm", temperature=0.1)
