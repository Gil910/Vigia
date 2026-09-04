"""Tests para vigia.targets — factory, HTTPTarget request building y response extraction."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vigia.targets import HTTPTarget, create_target


class TestHTTPTargetRequestBuilding:
    """Tests para _build_request de HTTPTarget."""

    def _make_target(self, **overrides):
        """Helper para crear un HTTPTarget con config mínima."""
        config = {
            "target": {
                "type": "http",
                "url": "https://api.test.com/chat",
                "request_format": "simple",
                "request_field": "message",
                "response_field": "response",
                **overrides,
            }
        }
        return HTTPTarget(config)

    def test_format_simple(self):
        target = self._make_target(request_format="simple", request_field="query")
        body = target._build_request("Hola mundo")
        assert body == {"query": "Hola mundo"}

    def test_format_openai(self):
        target = self._make_target(request_format="openai", model="gpt-4")
        body = target._build_request("Test prompt")
        assert "messages" in body
        assert body["messages"][0]["role"] == "user"
        assert body["messages"][0]["content"] == "Test prompt"
        assert body["model"] == "gpt-4"

    def test_format_openai_sin_modelo(self):
        target = self._make_target(request_format="openai")
        body = target._build_request("Test")
        assert "model" not in body

    def test_format_custom(self):
        template = '{"query": "{prompt}", "session": "test-123"}'
        target = self._make_target(
            request_format="custom",
            request_template=template,
        )
        body = target._build_request("Hola")
        assert body == {"query": "Hola", "session": "test-123"}

    def test_format_custom_escapa_comillas(self):
        """El prompt con comillas no debe romper el JSON del template."""
        template = '{"query": "{prompt}"}'
        target = self._make_target(
            request_format="custom",
            request_template=template,
        )
        body = target._build_request('Dime "la verdad"')
        assert body["query"] == 'Dime "la verdad"'

    def test_format_custom_sin_template_raises(self):
        target = self._make_target(request_format="custom")
        with pytest.raises(ValueError, match="request_template requerido"):
            target._build_request("Test")

    def test_format_invalido_raises(self):
        target = self._make_target(request_format="graphql")
        with pytest.raises(ValueError, match="request_format no soportado"):
            target._build_request("Test")

    def test_extra_body(self):
        config = {
            "target": {
                "type": "http",
                "url": "https://api.test.com/chat",
                "request_format": "simple",
                "request_field": "message",
                "response_field": "response",
                "extra_body": {"temperature": 0.5, "max_tokens": 100},
            }
        }
        target = HTTPTarget(config)
        body = target._build_request("Test")
        assert body["message"] == "Test"
        assert body["temperature"] == 0.5
        assert body["max_tokens"] == 100


class TestHTTPTargetResponseExtraction:
    """Tests para _extract_response de HTTPTarget."""

    def _make_target(self, response_field="response"):
        config = {
            "target": {
                "type": "http",
                "url": "https://api.test.com/chat",
                "request_format": "simple",
                "request_field": "message",
                "response_field": response_field,
            }
        }
        return HTTPTarget(config)

    def test_campo_directo(self):
        target = self._make_target("response")
        assert target._extract_response({"response": "Hola"}) == "Hola"

    def test_dot_notation_nested(self):
        target = self._make_target("data.answer")
        data = {"data": {"answer": "Respuesta interna"}}
        assert target._extract_response(data) == "Respuesta interna"

    def test_dot_notation_con_array(self):
        target = self._make_target("choices.0.message.content")
        data = {"choices": [{"message": {"content": "OpenAI style"}}]}
        assert target._extract_response(data) == "OpenAI style"

    def test_campo_no_encontrado_raises(self):
        target = self._make_target("nonexistent")
        with pytest.raises(ValueError, match="Campo.*no encontrado"):
            target._extract_response({"response": "test"})

    def test_indice_invalido_raises(self):
        target = self._make_target("choices.5.content")
        with pytest.raises(ValueError):
            target._extract_response({"choices": [{"content": "test"}]})

    def test_convierte_no_string_a_string(self):
        target = self._make_target("count")
        assert target._extract_response({"count": 42}) == "42"


class TestTargetFactory:
    """Tests para create_target."""

    def test_http_type_crea_http_target(self):
        config = {
            "target": {
                "type": "http",
                "url": "https://api.test.com/chat",
                "request_format": "simple",
                "request_field": "message",
                "response_field": "response",
            }
        }
        target = create_target(config)
        assert isinstance(target, HTTPTarget)

    def test_auto_con_url_crea_http_target(self):
        config = {
            "target": {
                "type": "auto",
                "url": "https://api.test.com/chat",
                "request_format": "simple",
                "request_field": "message",
                "response_field": "response",
            }
        }
        target = create_target(config)
        assert isinstance(target, HTTPTarget)

    def test_type_invalido_raises(self):
        config = {"target": {"type": "websocket"}}
        with pytest.raises(ValueError, match="Target type no soportado"):
            create_target(config)


class TestRAGTargetGenerationOptions:
    """The Ollama branch used to call ollama.chat(model, messages) and nothing
    else, so target.temperature was silently discarded on every local run."""

    def _target(self, extra=None):
        from vigia.targets import RAGTarget
        cfg = {"target": {"model": "qwen3:8b", "embed_model": "nomic-embed-text",
                          "system_prompt": "eres un bot", "temperature": 0.3,
                          **(extra or {})}}
        t = RAGTarget(cfg)
        t.vectorstore = SimpleNamespace(similarity_search=lambda q, k: [])
        return t

    @patch("vigia.targets.llm_chat", return_value="respuesta")
    def test_passes_temperature_and_caps_output(self, mock_chat):
        self._target().query("¿cuánto cobra Juan?")
        kw = mock_chat.call_args.kwargs
        assert kw["temperature"] == 0.3, "target.temperature must reach the model"
        assert kw["options"]["num_predict"] == 512
        assert kw["think"] is None

    @patch("vigia.targets.llm_chat", return_value="respuesta")
    def test_think_and_num_predict_are_configurable(self, mock_chat):
        self._target({"think": False, "num_predict": 128}).query("hola")
        kw = mock_chat.call_args.kwargs
        assert kw["think"] is False
        assert kw["options"]["num_predict"] == 128
