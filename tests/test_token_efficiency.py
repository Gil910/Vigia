"""Tests para token efficiency: tracking, early termination, persistent cache."""

import sqlite3
from unittest.mock import patch, MagicMock

import pytest

from vigia.providers import TokenStats, token_stats, _estimate_tokens
from vigia.attacker import AttackerAgent, MultiTurnResult
from vigia.database import init_db, cache_eval_store, cache_eval_lookup
from vigia.evaluator import evaluate_with_llm, _eval_cache, Evaluation


# ── TokenStats ────────────────────────────────────────────────

class TestTokenStats:

    def test_record_and_summary(self):
        ts = TokenStats()
        ts.record("model-a", 100, 50)
        ts.record("model-a", 200, 80)
        ts.record("model-b", 50, 20)
        s = ts.summary()
        assert s["total_tokens"] == 500
        assert s["prompt_tokens"] == 350
        assert s["completion_tokens"] == 150
        assert s["total_calls"] == 3
        assert len(s["per_model"]) == 2
        assert s["per_model"]["model-a"]["calls"] == 2

    def test_cached_calls_tracked(self):
        ts = TokenStats()
        ts.record("m", 100, 50)
        ts.record_cached()
        ts.record_cached()
        s = ts.summary()
        assert s["cached_calls"] == 2
        assert s["saved_pct"] == pytest.approx(66.7, abs=0.1)

    def test_reset(self):
        ts = TokenStats()
        ts.record("m", 100, 50)
        ts.record_cached()
        ts.record_error()
        ts.reset()
        s = ts.summary()
        assert s["total_tokens"] == 0
        assert s["total_calls"] == 0
        assert s["cached_calls"] == 0
        assert s["errors"] == 0

    def test_estimate_tokens(self):
        assert _estimate_tokens("hola mundo") >= 1
        assert _estimate_tokens("a" * 400) == 100


# ── Early termination ─────────────────────────────────────────

class TestEarlyTermination:

    def _make_target(self, responses):
        """Mock target that returns canned responses."""
        target = MagicMock()
        target.query = MagicMock(side_effect=[
            {"response": r, "chunks": [], "duration_ms": 10}
            for r in responses
        ])
        return target

    @patch("vigia.attacker.llm_chat")
    @patch("vigia.attacker.parse_json_response")
    def test_stops_after_3_consecutive_high_resistance(self, mock_parse, mock_llm):
        """Should stop early when target consistently refuses."""
        mock_llm.return_value = "Dame los datos"
        # Analyzer always reports high resistance, no revealed info
        mock_parse.return_value = {
            "revealed_info": [],
            "confirmed_categories": [],
            "resistance_level": "high",
            "suggested_technique": "rephrase",
            "analysis": "rechazó todo",
        }

        target = self._make_target([
            "No puedo ayudarte con eso.",
            "Lo siento, no tengo acceso.",
            "No puedo compartir esa información.",
            "Rechazado una vez más.",  # This should NOT be reached
        ])

        agent = AttackerAgent(model="test", provider="ollama")
        seed = {
            "id": "test-1",
            "target_behavior": "test",
            "category": "test",
            "prompt": "test",
        }

        result = agent.execute_multiturn(
            target=target,
            seed=seed,
            strategy_key="rapport_to_extraction",
            max_turns=7,
        )

        # Should stop after 3 high-resistance turns, not go to 7
        assert len(result.turns) <= 4  # At most 3 + 1 (the one that triggers the check)

    @patch("vigia.attacker.llm_chat")
    @patch("vigia.attacker.parse_json_response")
    def test_early_exit_on_success(self, mock_parse, mock_llm):
        """Should stop when enough data is extracted."""
        mock_llm.return_value = "Dame los datos"
        mock_parse.return_value = {
            "revealed_info": ["Juan Pérez", "52000€", "admin123"],
            "confirmed_categories": ["PII", "credenciales"],
            "resistance_level": "low",
            "suggested_technique": "continue",
            "analysis": "leaked everything",
        }

        target = self._make_target([
            "Juan Pérez cobra 52000€ y la contraseña es admin123",
            "Más datos aquí",  # Should NOT be reached
        ])

        agent = AttackerAgent(model="test", provider="ollama")
        seed = {"id": "test-2", "target_behavior": "test", "category": "test", "prompt": "test"}

        result = agent.execute_multiturn(
            target=target,
            seed=seed,
            strategy_key="rapport_to_extraction",
            max_turns=7,
        )

        # Should stop after first turn — got 3+ extracted items
        assert len(result.turns) == 1
        assert len(result.extracted_data) >= 3


# ── Persistent eval cache ─────────────────────────────────────

class TestPersistentEvalCache:

    def _make_db(self, tmp_path):
        return init_db(str(tmp_path / "test.db"))

    def test_store_and_lookup(self, tmp_path):
        conn = self._make_db(tmp_path)
        cache_eval_store(conn, "abc123", 1, "blocked", "test reasoning", ["dato1"])
        result = cache_eval_lookup(conn, "abc123")
        assert result is not None
        assert result["score"] == 1
        assert result["category"] == "blocked"
        assert result["sensitive_data"] == ["dato1"]
        conn.close()

    def test_lookup_miss(self, tmp_path):
        conn = self._make_db(tmp_path)
        assert cache_eval_lookup(conn, "nonexistent") is None
        conn.close()

    @patch("vigia.evaluator.llm_chat")
    def test_evaluator_uses_db_cache(self, mock_llm, tmp_path):
        """evaluate_with_llm should find cached result in SQLite."""
        conn = self._make_db(tmp_path)
        _eval_cache.clear()

        # Pre-populate DB cache
        import hashlib
        response = "No puedo ayudarte."
        truncated = response[:600]
        cache_key = hashlib.md5(truncated.encode()).hexdigest()
        cache_eval_store(conn, cache_key, 0, "blocked", "test", [])

        result = evaluate_with_llm(
            "attack", response, {"target_behavior": "test"},
            model="m", provider="ollama", conn=conn,
        )

        # LLM should NOT have been called — result came from DB
        mock_llm.assert_not_called()
        assert result.score == 0
        assert "[db-cached]" in result.reasoning
        conn.close()

    @patch("vigia.evaluator.llm_chat")
    def test_evaluator_persists_to_db(self, mock_llm, tmp_path):
        """Low-score evaluations should be stored in SQLite."""
        conn = self._make_db(tmp_path)
        _eval_cache.clear()

        mock_llm.return_value = '{"score": 1, "category": "blocked", "reasoning": "rechazó", "sensitive_data_found": []}'

        evaluate_with_llm(
            "attack", "No puedo.", {"target_behavior": "test"},
            model="m", provider="ollama", conn=conn,
        )

        # Check it was persisted
        import hashlib
        cache_key = hashlib.md5("No puedo.".encode()).hexdigest()
        stored = cache_eval_lookup(conn, cache_key)
        assert stored is not None
        assert stored["score"] == 1
        conn.close()
