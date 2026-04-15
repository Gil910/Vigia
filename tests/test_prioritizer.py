"""Tests para vigia.prioritizer — Smart seed ordering from session memory."""

import os
import tempfile
import pytest
from vigia.prioritizer import prioritize_seeds
from vigia.database import init_db, create_campaign, record_learning


@pytest.fixture
def db_conn():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_prio.db")
        conn = init_db(db_path)
        yield conn
        conn.close()


def _seed(vector: str, seed_id: str = None) -> dict:
    return {
        "id": seed_id or f"seed-{vector}",
        "vector": vector,
        "category": "test",
        "owasp": "LLM02",
        "language": "es-ES",
        "prompt": "test",
        "target_behavior": "test",
        "severity": "high",
    }


class TestPrioritizeSeeds:
    def test_no_conn_returns_as_is(self):
        seeds = [_seed("v01"), _seed("v02")]
        result, skipped = prioritize_seeds(seeds, None, "model")
        assert result == seeds
        assert skipped == []

    def test_no_history_returns_as_is(self, db_conn):
        seeds = [_seed("v01"), _seed("v02")]
        result, skipped = prioritize_seeds(seeds, db_conn, "model")
        assert len(result) == 2
        assert skipped == []

    def test_orders_by_success_rate(self, db_conn):
        cid = create_campaign(db_conn, "test", "llama3.1:8b", {})

        # v01: 100% success (score 8)
        record_learning(db_conn, cid, "llama3.1:8b", {
            "seed_id": "s1", "vector": "v01", "score": 8,
            "language": "es-ES", "owasp": "LLM02",
        })
        # v02: 0% success (score 2)
        record_learning(db_conn, cid, "llama3.1:8b", {
            "seed_id": "s2", "vector": "v02", "score": 2,
            "language": "es-ES", "owasp": "LLM02",
        })

        seeds = [_seed("v02"), _seed("v01")]  # v02 first (worse)
        result, skipped = prioritize_seeds(seeds, db_conn, "llama3.1:8b")

        # v01 should come first (higher success rate)
        assert result[0]["vector"] == "v01"
        assert result[1]["vector"] == "v02"

    def test_skips_zero_success_after_threshold(self, db_conn):
        cid = create_campaign(db_conn, "test", "mistral", {})

        # v01: 0% success with 6 attempts (above default threshold of 5)
        for i in range(6):
            record_learning(db_conn, cid, "mistral", {
                "seed_id": f"s-{i}", "vector": "v01", "score": 1,
                "language": "es-ES", "owasp": "LLM02",
            })

        # v02: has history, is effective
        record_learning(db_conn, cid, "mistral", {
            "seed_id": "s-ok", "vector": "v02", "score": 9,
            "language": "es-ES", "owasp": "LLM02",
        })

        seeds = [_seed("v01"), _seed("v02")]
        result, skipped = prioritize_seeds(seeds, db_conn, "mistral")

        assert len(result) == 1
        assert result[0]["vector"] == "v02"
        assert len(skipped) == 1
        assert skipped[0]["vector"] == "v01"

    def test_does_not_skip_below_threshold(self, db_conn):
        cid = create_campaign(db_conn, "test", "model", {})

        # Only 3 attempts (below default 5) — don't skip yet
        for i in range(3):
            record_learning(db_conn, cid, "model", {
                "seed_id": f"s-{i}", "vector": "v01", "score": 0,
                "language": "es-ES", "owasp": "LLM02",
            })

        seeds = [_seed("v01")]
        result, skipped = prioritize_seeds(seeds, db_conn, "model")
        assert len(result) == 1
        assert len(skipped) == 0

    def test_unknown_vectors_included_after_known(self, db_conn):
        cid = create_campaign(db_conn, "test", "model", {})
        record_learning(db_conn, cid, "model", {
            "seed_id": "s1", "vector": "v01", "score": 8,
            "language": "es-ES", "owasp": "LLM02",
        })

        seeds = [_seed("new_vector"), _seed("v01")]
        result, skipped = prioritize_seeds(seeds, db_conn, "model")

        assert result[0]["vector"] == "v01"      # known effective → first
        assert result[1]["vector"] == "new_vector"  # unknown → second

    def test_skip_disabled_with_zero_threshold(self, db_conn):
        cid = create_campaign(db_conn, "test", "model", {})
        for i in range(10):
            record_learning(db_conn, cid, "model", {
                "seed_id": f"s-{i}", "vector": "v01", "score": 0,
            })

        seeds = [_seed("v01")]
        result, skipped = prioritize_seeds(
            seeds, db_conn, "model", skip_zero_success_after=0,
        )
        assert len(result) == 1
        assert len(skipped) == 0

    def test_different_models_independent(self, db_conn):
        cid = create_campaign(db_conn, "test", "mistral", {})
        # v01 fails 100% on mistral
        for i in range(6):
            record_learning(db_conn, cid, "mistral", {
                "seed_id": f"s-{i}", "vector": "v01", "score": 0,
            })

        seeds = [_seed("v01")]

        # Against mistral: skipped
        _, skipped_mistral = prioritize_seeds(seeds, db_conn, "mistral")
        assert len(skipped_mistral) == 1

        # Against llama: no history, not skipped
        result_llama, skipped_llama = prioritize_seeds(seeds, db_conn, "llama3.1:8b")
        assert len(result_llama) == 1
        assert len(skipped_llama) == 0
