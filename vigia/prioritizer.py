"""
VIGÍA — Smart Seed Prioritizer v0.1
Uses accumulated session memory to reorder seeds by expected effectiveness.
Seeds targeting vectors with higher historical success rates run first.
Optionally skips vectors with 0% success rate after N attempts.
"""

import sqlite3
from typing import Optional

from vigia.database import get_vector_effectiveness


def prioritize_seeds(
    seeds: list[dict],
    conn: Optional[sqlite3.Connection],
    target_model: str,
    skip_zero_success_after: int = 5,
) -> tuple[list[dict], list[dict]]:
    """
    Reorder seeds by historical vector effectiveness against target_model.
    Seeds with unknown vectors (no history) go after known-effective ones.
    Seeds with 0% success rate after N+ attempts are separated as skipped.

    Args:
        seeds: List of seed dicts with at least 'vector' key
        conn: DB connection (None = no prioritization, return as-is)
        target_model: Model identifier to look up history for
        skip_zero_success_after: Min attempts before skipping 0% vectors.
                                  Set to 0 to disable skipping.

    Returns:
        (prioritized_seeds, skipped_seeds)
    """
    if conn is None:
        return seeds, []

    effectiveness = get_vector_effectiveness(conn, target_model)
    if not effectiveness:
        # No history — return seeds as-is
        return seeds, []

    # Build lookup: vector → {success_rate, total_attempts, avg_score}
    vector_stats = {}
    for eff in effectiveness:
        attempts = max(eff["total_attempts"], 1)
        vector_stats[eff["vector"]] = {
            "success_rate": eff["total_successes"] / attempts,
            "total_attempts": eff["total_attempts"],
            "avg_score": eff["avg_score"],
        }

    prioritized = []
    skipped = []

    for seed in seeds:
        vector = seed.get("vector", "unknown")
        stats = vector_stats.get(vector)

        if stats is None:
            # Unknown vector — include (could be new and effective)
            prioritized.append(seed)
        elif (
            skip_zero_success_after > 0
            and stats["success_rate"] == 0.0
            and stats["total_attempts"] >= skip_zero_success_after
        ):
            # Proven ineffective — skip
            skipped.append(seed)
        else:
            prioritized.append(seed)

    # Sort prioritized: highest success rate first, unknown vectors last
    def _sort_key(seed: dict) -> tuple[int, float, float]:
        vector = seed.get("vector", "unknown")
        stats = vector_stats.get(vector)
        if stats is None:
            # Unknown: sort after known vectors, but before 0% ones
            return (1, 0.0, 0.0)
        return (0, -stats["success_rate"], -stats["avg_score"])

    prioritized.sort(key=_sort_key)

    return prioritized, skipped
