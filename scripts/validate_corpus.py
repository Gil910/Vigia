#!/usr/bin/env python3
"""Schema and taxonomy check for the attack corpus. Runs in CI.

A seed with a missing field does not fail at load time, it fails halfway through a
campaign an hour later. Cheaper to catch here.

The taxonomy half of this matters more than it looks. Checking that `owasp` is one
of LLM01..LLM10 catches nothing, because that is the same ten strings in the 2023
list and the 2026 one — a corpus can be entirely unmigrated and still pass. So the
check is against the canonical vector->category map in
`scripts/remap_owasp_2026.py`: a seed whose vector says one thing and whose OWASP
ID says another is a failure, and so is a vector nobody has classified.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from remap_owasp_2026 import AGENTIC, RAG  # noqa: E402

RAG_REQUIRED = {"id", "vector", "category", "owasp", "atlas", "language",
                "prompt", "target_behavior", "severity"}
AGENT_REQUIRED = {"id", "vector", "category", "owasp_agentic", "language",
                  "prompt", "target_behavior", "severity"}
DEAD_FIELDS = {"owasp_secondary", "legacy_id"}
SEVERITIES = {"low", "medium", "high", "critical"}
LOCALES = {"es-ES", "ca-ES", "eu-ES", "gl-ES", "es-CA", "es-EU", "es-GL", "en-US"}

SEEDS = Path(__file__).parent.parent / "vigia/corpus/seeds"
problems = []


def check(filename, required, taxonomy_field, canonical):
    seeds = json.loads((SEEDS / filename).read_text(encoding="utf-8"))
    seen = set()
    for i, s in enumerate(seeds):
        where = f"{filename}[{i}] {s.get('id', '?')}"

        missing = required - s.keys()
        if missing:
            problems.append(f"{where}: missing {sorted(missing)}")
        stale = DEAD_FIELDS & s.keys()
        if stale:
            problems.append(f"{where}: carries dropped field(s) {sorted(stale)}")

        if s.get("id") in seen:
            problems.append(f"{where}: duplicate id")
        seen.add(s.get("id"))

        expected = canonical.get(s.get("vector"))
        if expected is None:
            problems.append(
                f"{where}: vector {s.get('vector')!r} has no entry in "
                f"scripts/remap_owasp_2026.py, so nothing pins its taxonomy"
            )
        else:
            want_id, want_category = expected
            if s.get(taxonomy_field) != want_id:
                problems.append(
                    f"{where}: {taxonomy_field}={s.get(taxonomy_field)!r} but vector "
                    f"{s['vector']} maps to {want_id} in the 2026 list"
                )
            if s.get("category") != want_category:
                problems.append(
                    f"{where}: category={s.get('category')!r}, expected {want_category!r}"
                )

        if s.get("severity") not in SEVERITIES:
            problems.append(f"{where}: severity={s.get('severity')!r}")
        if s.get("language") not in LOCALES:
            problems.append(f"{where}: language={s.get('language')!r}")
        if not (s.get("prompt") or "").strip():
            problems.append(f"{where}: empty prompt")
    return len(seeds)


total = 0
total += check("seeds_validated.json", RAG_REQUIRED, "owasp", RAG)
total += check("seeds_mutated.json", RAG_REQUIRED, "owasp", RAG)
total += check("agent_seeds.json", AGENT_REQUIRED, "owasp_agentic", AGENTIC)

if problems:
    print(f"{len(problems)} problem(s) in {total} seeds:\n")
    for p in problems[:40]:
        print(" ", p)
    if len(problems) > 40:
        print(f"  ... and {len(problems) - 40} more")
    sys.exit(1)

print(f"{total} seeds, schema and 2026 taxonomy clean")
