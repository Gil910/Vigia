"""
VIGÍA — Provider Abstraction Layer
Centraliza las llamadas a LLMs (Ollama local y LiteLLM para APIs externas).
Elimina duplicación entre attacker, evaluator y mutation_engine.
"""

import json
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Retry config for rate-limited APIs (Gemini free tier, etc.)
MAX_RETRIES = 5
BASE_DELAY = 4.0  # seconds


# ── Token tracking ───────────────────────────────────────────────
@dataclass
class TokenStats:
    """Tracks token usage across a campaign/session."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_calls: int = 0
    cached_calls: int = 0
    errors: int = 0
    _per_model: dict = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def record(self, model: str, prompt_toks: int, completion_toks: int) -> None:
        self.prompt_tokens += prompt_toks
        self.completion_tokens += completion_toks
        self.total_calls += 1
        if model not in self._per_model:
            self._per_model[model] = {"prompt": 0, "completion": 0, "calls": 0}
        self._per_model[model]["prompt"] += prompt_toks
        self._per_model[model]["completion"] += completion_toks
        self._per_model[model]["calls"] += 1

    def record_cached(self) -> None:
        self.cached_calls += 1

    def record_error(self) -> None:
        self.errors += 1

    def summary(self) -> dict:
        saved_pct = (self.cached_calls / max(1, self.total_calls + self.cached_calls)) * 100
        return {
            "total_tokens": self.total_tokens,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_calls": self.total_calls,
            "cached_calls": self.cached_calls,
            "saved_pct": round(saved_pct, 1),
            "errors": self.errors,
            "per_model": dict(self._per_model),
        }

    def reset(self) -> None:
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_calls = 0
        self.cached_calls = 0
        self.errors = 0
        self._per_model.clear()


# Global token tracker — shared across campaign
token_stats = TokenStats()


def _estimate_tokens(text: str) -> int:
    """Quick token estimation: ~4 chars per token for Spanish/English."""
    return max(1, len(text) // 4)


def llm_chat(
    model: str,
    messages: list[dict],
    provider: str = "ollama",
    temperature: float = 0.3,
) -> str:
    """
    Envía mensajes a un LLM y devuelve el texto de respuesta.

    Args:
        model: Nombre del modelo (ej: "llama3.1:8b", "anthropic/claude-haiku-4-5-20251001")
        messages: Lista de mensajes [{"role": "system/user/assistant", "content": "..."}]
        provider: "ollama" para local, "litellm" para APIs externas
        temperature: Temperatura de generación (0.0-1.0)

    Returns:
        Texto de respuesta del modelo

    Raises:
        ValueError: Si el provider no es soportado
        RuntimeError: Si litellm no está instalado o hay error de conexión
    """
    if provider == "ollama":
        return _call_ollama(model, messages, temperature)
    elif provider == "litellm":
        return _call_litellm(model, messages, temperature)
    else:
        raise ValueError(f"Provider no soportado: {provider}. Usa 'ollama' o 'litellm'.")


def _call_ollama(model: str, messages: list[dict], temperature: float) -> str:
    """Llama al modelo via Ollama local."""
    import ollama
    response = ollama.chat(
        model=model,
        messages=messages,
        options={"temperature": temperature},
    )
    content = response["message"]["content"]
    # Track tokens (Ollama returns actual counts in some versions)
    prompt_toks = response.get("prompt_eval_count", _estimate_tokens(
        "".join(m["content"] for m in messages)
    ))
    completion_toks = response.get("eval_count", _estimate_tokens(content))
    token_stats.record(model, prompt_toks, completion_toks)
    return content


def _call_litellm(model: str, messages: list[dict], temperature: float) -> str:
    """Llama al modelo via LiteLLM con retry exponencial para rate limits."""
    try:
        import litellm
    except ImportError:
        raise RuntimeError(
            "litellm no instalado. Ejecuta: pip install litellm\n"
            "Y configura la API key correspondiente:\n"
            "  export ANTHROPIC_API_KEY=sk-...\n"
            "  export OPENAI_API_KEY=sk-...\n"
            "  export GEMINI_API_KEY=..."
        )

    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            response = litellm.completion(
                model=model,
                messages=messages,
                temperature=temperature,
            )
            content = response.choices[0].message.content
            # Track tokens from API response (exact counts)
            usage = getattr(response, "usage", None)
            if usage:
                token_stats.record(
                    model,
                    getattr(usage, "prompt_tokens", 0),
                    getattr(usage, "completion_tokens", 0),
                )
            else:
                token_stats.record(
                    model,
                    _estimate_tokens("".join(m["content"] for m in messages)),
                    _estimate_tokens(content or ""),
                )
            return content
        except Exception as e:
            error_str = str(e).lower()
            exc_type = type(e).__name__.lower()
            is_retryable = any(
                kw in error_str or kw in exc_type
                for kw in (
                    "rate_limit", "rate limit", "ratelimit",
                    "429", "quota", "resource_exhausted",
                    "retrydelay", "retry", "too many requests",
                    "503", "service unavailable", "overloaded",
                )
            )
            if is_retryable and attempt < MAX_RETRIES - 1:
                delay = BASE_DELAY * (2 ** attempt)
                print(f"  ⏳ Rate limit ({model}), retry {attempt + 1}/{MAX_RETRIES} in {delay:.0f}s...")
                time.sleep(delay)
                last_error = e
            else:
                if attempt == 0:
                    logger.debug(f"[vigia] Non-retryable error ({model}): {exc_type}: {str(e)[:200]}")
                raise

    raise last_error  # type: ignore[misc]


def parse_json_response(raw: str) -> Optional[dict]:
    """
    Intenta extraer un objeto JSON de una respuesta de LLM.
    Maneja backticks de markdown, texto antes/después del JSON, etc.

    Returns:
        dict parseado o None si no se pudo parsear
    """
    cleaned = raw.strip()

    # Quitar backticks markdown
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    # Encontrar JSON en la respuesta
    start = cleaned.find("{")
    end = cleaned.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            return json.loads(cleaned[start:end])
        except json.JSONDecodeError:
            pass

    return None
