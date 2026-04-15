"""Tests para vigia.hooks — Hook system y session memory integration."""

import os
import tempfile
import pytest
from vigia.hooks import (
    HookRegistry,
    HookEvent,
    HookContext,
    make_learning_hook,
    make_log_hook,
)
from vigia.database import (
    init_db,
    create_campaign,
    record_learning,
    get_vector_effectiveness,
    get_model_resistance_profile,
)


# ─── Fixtures ────────────────────────────────────────────────


@pytest.fixture
def registry():
    return HookRegistry()


@pytest.fixture
def db_conn():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_hooks.db")
        conn = init_db(db_path)
        yield conn
        conn.close()


def _make_seed(
    seed_id: str = "ES-V01-001",
    vector: str = "numerical_anchor",
    owasp: str = "LLM02",
    language: str = "es-ES",
) -> dict:
    return {
        "id": seed_id,
        "vector": vector,
        "category": "sensitive_information_disclosure",
        "owasp": owasp,
        "language": language,
        "prompt": "test prompt",
        "target_behavior": "reveal salary",
        "severity": "high",
    }


# ─── HookRegistry Tests ─────────────────────────────────────


class TestHookRegistry:
    def test_register_and_fire(self, registry):
        fired = []
        registry.register(HookEvent.PRE_ATTACK, lambda ctx: fired.append(ctx.event))
        registry.fire(HookEvent.PRE_ATTACK, HookContext(event=HookEvent.PRE_ATTACK))
        assert fired == [HookEvent.PRE_ATTACK]

    def test_multiple_callbacks_same_event(self, registry):
        results = []
        registry.register(HookEvent.POST_EVALUATE, lambda ctx: results.append("a"))
        registry.register(HookEvent.POST_EVALUATE, lambda ctx: results.append("b"))
        registry.fire(HookEvent.POST_EVALUATE, HookContext(event=HookEvent.POST_EVALUATE))
        assert results == ["a", "b"]

    def test_fire_wrong_event_does_nothing(self, registry):
        fired = []
        registry.register(HookEvent.PRE_ATTACK, lambda ctx: fired.append(True))
        registry.fire(HookEvent.POST_ATTACK, HookContext(event=HookEvent.POST_ATTACK))
        assert fired == []

    def test_callback_error_does_not_propagate(self, registry):
        """Errors in hooks are swallowed, not raised."""
        def bad_hook(ctx):
            raise ValueError("boom")

        ok_results = []
        registry.register(HookEvent.POST_EVALUATE, bad_hook)
        registry.register(HookEvent.POST_EVALUATE, lambda ctx: ok_results.append("ok"))
        # Should not raise
        registry.fire(HookEvent.POST_EVALUATE, HookContext(event=HookEvent.POST_EVALUATE))
        assert ok_results == ["ok"]

    def test_clear_specific_event(self, registry):
        fired = []
        registry.register(HookEvent.PRE_ATTACK, lambda ctx: fired.append("pre"))
        registry.register(HookEvent.POST_ATTACK, lambda ctx: fired.append("post"))
        registry.clear(HookEvent.PRE_ATTACK)
        registry.fire(HookEvent.PRE_ATTACK, HookContext(event=HookEvent.PRE_ATTACK))
        registry.fire(HookEvent.POST_ATTACK, HookContext(event=HookEvent.POST_ATTACK))
        assert fired == ["post"]

    def test_clear_all_events(self, registry):
        fired = []
        registry.register(HookEvent.PRE_ATTACK, lambda ctx: fired.append("pre"))
        registry.register(HookEvent.POST_ATTACK, lambda ctx: fired.append("post"))
        registry.clear()
        registry.fire(HookEvent.PRE_ATTACK, HookContext(event=HookEvent.PRE_ATTACK))
        registry.fire(HookEvent.POST_ATTACK, HookContext(event=HookEvent.POST_ATTACK))
        assert fired == []

    def test_decorator_registration(self, registry):
        results = []

        @registry.on(HookEvent.CAMPAIGN_START)
        def on_start(ctx):
            results.append(ctx.target_model)

        registry.fire(HookEvent.CAMPAIGN_START, HookContext(
            event=HookEvent.CAMPAIGN_START, target_model="test-model",
        ))
        assert results == ["test-model"]

    def test_context_modification(self, registry):
        """Callbacks can modify and return context."""
        def enrich(ctx):
            ctx.metadata["enriched"] = True
            return ctx

        registry.register(HookEvent.POST_ATTACK, enrich)
        ctx = registry.fire(HookEvent.POST_ATTACK, HookContext(event=HookEvent.POST_ATTACK))
        assert ctx.metadata.get("enriched") is True


# ─── Learning Hook Tests ─────────────────────────────────────


class TestLearningHook:
    def test_records_learning_on_post_evaluate(self, db_conn):
        cid = create_campaign(db_conn, "test", "llama3.1:8b", {})
        hook = make_learning_hook(db_conn, cid, "llama3.1:8b", threshold=5)

        ctx = HookContext(
            event=HookEvent.POST_EVALUATE,
            campaign_id=cid,
            seed=_make_seed(),
            score=8,
            target_model="llama3.1:8b",
        )
        hook(ctx)

        rows = db_conn.execute(
            "SELECT * FROM campaign_learnings WHERE campaign_id = ?", (cid,)
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["score"] == 8
        assert rows[0]["success"] == 1
        assert rows[0]["vector"] == "numerical_anchor"

    def test_records_failed_attack_as_learning(self, db_conn):
        cid = create_campaign(db_conn, "test", "llama3.1:8b", {})
        hook = make_learning_hook(db_conn, cid, "llama3.1:8b", threshold=5)

        ctx = HookContext(
            event=HookEvent.POST_EVALUATE,
            seed=_make_seed(),
            score=2,
            target_model="llama3.1:8b",
        )
        hook(ctx)

        rows = db_conn.execute("SELECT * FROM campaign_learnings").fetchall()
        assert len(rows) == 1
        assert rows[0]["success"] == 0
        assert rows[0]["resistance_pattern"] == "partial_resist"

    def test_skips_when_no_seed(self, db_conn):
        cid = create_campaign(db_conn, "test", "model", {})
        hook = make_learning_hook(db_conn, cid, "model")

        ctx = HookContext(event=HookEvent.POST_EVALUATE, score=5, seed=None)
        hook(ctx)  # Should not raise

        rows = db_conn.execute("SELECT * FROM campaign_learnings").fetchall()
        assert len(rows) == 0

    def test_updates_vector_effectiveness(self, db_conn):
        cid = create_campaign(db_conn, "test", "mistral", {})
        hook = make_learning_hook(db_conn, cid, "mistral", threshold=5)

        # Fire 3 attacks on same vector: 2 success, 1 fail
        for score in [8, 6, 2]:
            hook(HookContext(
                event=HookEvent.POST_EVALUATE,
                seed=_make_seed(seed_id=f"seed-{score}"),
                score=score,
            ))

        effectiveness = get_vector_effectiveness(db_conn, "mistral")
        assert len(effectiveness) == 1
        eff = effectiveness[0]
        assert eff["vector"] == "numerical_anchor"
        assert eff["total_attempts"] == 3
        assert eff["total_successes"] == 2


# ─── Session Memory (DB) Tests ───────────────────────────────


class TestSessionMemory:
    def test_resistance_patterns(self, db_conn):
        cid = create_campaign(db_conn, "test", "llama3.1:8b", {})

        # full_block (score 0), partial_resist (score 3), vulnerable (score 6), critical_fail (score 9)
        patterns = [
            ("seed-1", 0, "full_block"),
            ("seed-2", 3, "partial_resist"),
            ("seed-3", 6, "vulnerable"),
            ("seed-4", 9, "critical_fail"),
        ]
        for seed_id, score, expected_pattern in patterns:
            record_learning(db_conn, cid, "llama3.1:8b", {
                "seed_id": seed_id, "vector": "test", "score": score,
                "language": "es-ES", "owasp": "LLM02",
            })

        rows = db_conn.execute(
            "SELECT seed_id, resistance_pattern FROM campaign_learnings ORDER BY id"
        ).fetchall()
        for i, (_, _, expected) in enumerate(patterns):
            assert rows[i]["resistance_pattern"] == expected

    def test_model_resistance_profile(self, db_conn):
        cid = create_campaign(db_conn, "test", "mistral", {})

        vectors = [
            ("numerical_anchor", 9),
            ("numerical_anchor", 8),
            ("summary_exfil", 2),
            ("summary_exfil", 1),
            ("role_impersonation", 6),
        ]
        for vector, score in vectors:
            record_learning(db_conn, cid, "mistral", {
                "seed_id": f"seed-{vector}-{score}",
                "vector": vector,
                "score": score,
                "language": "es-ES",
                "owasp": "LLM02",
            })

        profile = get_model_resistance_profile(db_conn, "mistral")
        assert profile["model"] == "mistral"
        assert profile["total_attacks"] == 5

        # Weakest = numerical_anchor (avg 8.5)
        assert profile["weakest_defenses"][0]["vector"] == "numerical_anchor"
        # Strongest = summary_exfil (avg 1.5)
        assert profile["strongest_defenses"][0]["vector"] == "summary_exfil"

    def test_cross_campaign_accumulation(self, db_conn):
        """Learnings accumulate across campaigns for same model."""
        cid1 = create_campaign(db_conn, "c1", "llama3.1:8b", {})
        cid2 = create_campaign(db_conn, "c2", "llama3.1:8b", {})

        record_learning(db_conn, cid1, "llama3.1:8b", {
            "seed_id": "s1", "vector": "v01", "score": 8,
            "language": "es-ES", "owasp": "LLM02",
        })
        record_learning(db_conn, cid2, "llama3.1:8b", {
            "seed_id": "s2", "vector": "v01", "score": 3,
            "language": "ca-ES", "owasp": "LLM02",
        })

        effectiveness = get_vector_effectiveness(db_conn, "llama3.1:8b")
        assert len(effectiveness) == 1
        assert effectiveness[0]["total_attempts"] == 2

    def test_negative_score_skipped(self, db_conn):
        cid = create_campaign(db_conn, "test", "model", {})
        record_learning(db_conn, cid, "model", {
            "seed_id": "err", "vector": "test", "score": -1,
        })
        rows = db_conn.execute("SELECT * FROM campaign_learnings").fetchall()
        assert len(rows) == 0


# ─── Integration: Hook + Session Memory ──────────────────────


class TestHookSessionMemoryIntegration:
    def test_full_pipeline_hook_records_learnings(self, db_conn):
        """Simulate a mini campaign: hooks record learnings as attacks are evaluated."""
        cid = create_campaign(db_conn, "integration", "gemma2:2b", {})

        registry = HookRegistry()
        registry.register(
            HookEvent.POST_EVALUATE,
            make_learning_hook(db_conn, cid, "gemma2:2b", threshold=5),
        )

        # Simulate 5 attacks
        seeds = [
            _make_seed("s1", "numerical_anchor", "LLM02", "es-ES"),
            _make_seed("s2", "summary_exfil", "LLM02", "es-ES"),
            _make_seed("s3", "role_impersonation", "LLM01", "es-ES"),
            _make_seed("s4", "cross_language", "LLM01", "ca-ES"),
            _make_seed("s5", "numerical_anchor", "LLM02", "eu-ES"),
        ]
        scores = [9, 3, 7, 1, 6]

        for seed, score in zip(seeds, scores):
            registry.fire(HookEvent.POST_EVALUATE, HookContext(
                event=HookEvent.POST_EVALUATE,
                campaign_id=cid,
                seed=seed,
                score=score,
                target_model="gemma2:2b",
            ))

        # Verify learnings
        rows = db_conn.execute("SELECT * FROM campaign_learnings").fetchall()
        assert len(rows) == 5

        # Verify vector effectiveness
        eff = get_vector_effectiveness(db_conn, "gemma2:2b")
        vectors = {e["vector"]: e for e in eff}
        assert vectors["numerical_anchor"]["total_attempts"] == 2
        assert vectors["numerical_anchor"]["total_successes"] == 2  # scores 9,6

        # Verify resistance profile
        profile = get_model_resistance_profile(db_conn, "gemma2:2b")
        assert profile["total_attacks"] == 5
        assert profile["weakest_defenses"][0]["vector"] == "numerical_anchor"
