# Changelog

## 0.6.0 — 2026-08-18

Mostly a correctness release. Nothing new to attack with; a fair amount that was
wrong is now right.

### Taxonomy

- Corpus remapped to the **OWASP GenAI LLM Top 10 2026** (published 3 August 2026).
  Eleven of the nineteen RAG vectors changed ID; three more kept LLM02 while LLM02
  itself changed meaning, so fourteen of nineteen were pointing at something other
  than what the corpus assumed. `docs/TAXONOMY.md` has the old-to-new table and
  `scripts/remap_owasp_2026.py` is the migration, which reproduces the shipped
  corpus from a pre-2026 one and is idempotent.
- The `category` field on each seed was still the 2023 names, so seeds sat under
  `training_data_poisoning` in a category whose whole point is that it is
  extraction rather than poisoning. Migrated with `owasp`, and the validator now
  enforces that the two agree.
- Agentic seeds remapped to the **OWASP Top 10 for Agentic Applications 2026**
  (ASI01–ASI10). The old draft used ASI04 for excessive agency and ASI05/ASI06 for
  "inadequate sandboxing"; in the published list those are Agentic Supply Chain
  Compromise, Unexpected Code Execution and Memory & Context Poisoning. Different
  categories, not a renumbering.
- **The agent pipeline was emitting the draft IDs too.** `agents/evaluator.py`
  tagged out-of-mandate actions ASI04 and information disclosure ASI06;
  `agents/planner.py` generated ASI04 vectors; `agents/remediation.py` filed
  rate-limiting advice under ASI04 and system-prompt protection under ASI06 with a
  reference to "LLM07 System Prompt Leakage". Migrating the data without the code
  would have produced reports that mislabel every agentic finding.
- **`reporting/generator.py` had two hand-maintained copies of an OWASP ID-to-name
  table**, both pre-2026, already drifted from each other (ASI05 and ASI06 both
  said "Inadequate Sandboxing"), and covering 2 of the 10 LLM categories. Seven of
  the eight LLM codes the corpus actually uses rendered with no name at all. One
  table now, complete, at module level.
- Agentic seed IDs are sequential (`AGT-001`…) instead of encoding an ASI number
  that gets reassigned every year. One duplicate ID fixed in passing.
- Two coverage gaps documented rather than papered over: no seeds for LLM05 (Data
  and Model Poisoning) or LLM07 (Misinformation), and five of the ten ASI
  categories are empty.

### Fixes

- **The judge cache was keyed on the response text alone.** Two turns of one
  conversation can produce identical responses off completely different prompts,
  and the second silently inherited the first's verdict. In this project's own
  database, 9 response strings were scored ≤2 in one place and ≥5 in another;
  `"Lo siento, pero no puedo cumplir con esa solicitud."` appears 158 times with
  scores from 0 to 10. The key now covers prompt, response and target behaviour,
  with a regression test. 133 of the 2,769 published results (4.8%) came through
  the old cache and are disclosed as possible false negatives in
  `docs/METHODOLOGY.md`; none of them are Catalan.
- **The deterministic attack templates never fired.** `_mutate_prompt` and the
  tier-3 fallback looked up topics in the seed's `category` field, but the keys
  they searched for (`salary_disclosure`, `credential_exposure`…) live in
  `target_behavior`. Against a real seed the lookup matched nothing and every
  mutation fell through to one generic sentence. 90 of 195 seeds now get a
  topic-specific mutation, up from 0. The test that covered this passed because it
  set `category` by hand to a value no seed carries.
- `vigia --version` reported 0.4.0 since v0.5: the number was hardcoded in
  `cli.py` while `pyproject.toml` said 0.5.3 and three modules carried their own
  stamps in a docstring. One source of truth in `vigia/__init__.py` now.
- Repository URL in `pyproject.toml` and in the CLI banner pointed at a GitHub
  account that does not exist, so every link on the PyPI page 404'd since 0.5.3.
  README links are absolute now too, because PyPI cannot resolve repo-relative
  paths and half the project page was dead.
- Multi-turn campaigns evaluated the last turn twice, once alone and again inside
  the all-turns loop. One wasted judge call per seed.
- Multi-turn results stored the last turn's response next to the best turn's
  score. The stored row now names the turn it was scored on.
- `_extract_response` in the HTTP target shadowed `dataclasses.field` with its
  loop variable. Exceptions there and in the LiteLLM provider chain with `from`.

### Results

- **317 errored attacks are no longer counted as clean.** Attacks that never
  reached the judge (timeouts, an expired key, an unreachable HTTP target) scored
  -1 and sat in the denominator. Excluding them: Catalan 59.6% → 70.0%, Spanish
  37.8% → 45.8%. 2,769 evaluated, not 3,086.
- **Corrected the judge attribution on the cross-model benchmark.** It was
  documented as using Claude Haiku 4.5 as the evaluator. It used llama3.1:8b,
  which is also one of the four targets it ranks. Written up rather than quietly
  corrected; re-running it under a neutral judge is the top open item.
- Per-vector table was labelled "global" but computed over a subset. Regenerated.
- Added run-to-run variance: the same config against the same 195 seeds twice
  holds the aggregate rate to about a point but flips 12–14% of individual
  verdicts. That is the number that matters if you gate CI on this.
- `scripts/stats.py` emits `docs/RESULTS.md` in full, including the cache exposure
  above. No figure in either README is typed by hand.
- The MITRE ATLAS column is documented as the weakest mapping in the project
  rather than presented as authoritative. A third of the corpus carries
  `AML.T0048.004`, which is AI Intellectual Property Theft, on seeds whose job is
  to leak a salary. Not fixed, and said so.

### Repository

- `ruff check` and `pytest` run in CI across Python 3.11–3.13, plus a corpus
  check. Lint went from 174 findings to zero. 373 tests, all green.
- `scripts/validate_corpus.py` validates against the canonical vector-to-category
  map, not against the set of legal IDs — LLM01..LLM10 is the same ten strings in
  2023 and 2026, so an ID-only check cannot tell a migrated corpus from an
  unmigrated one. It found the duplicate agentic ID on its first run.
- Untracked from git: the ChromaDB binaries under `results/`, `run_demo.log`, a
  LinkedIn draft, and the local agent config under `.claude/`.
- `SECURITY.md` with an authorised-use statement, `CONTRIBUTING.md`, this file,
  and `docs/METHODOLOGY.md`.
- README rewritten in English with a full Spanish version at `README.es.md`.

## 0.5.3 — 2026-04-15

- +156 mutated seeds in eu-ES, gl-ES, es-EU and es-GL. 195 seeds total.
- Cross-model benchmark, 195 seeds against four targets.
- Measured evaluator bias: llama-as-judge vs claude-as-judge over the same 135
  attacks, 23.0% vs 14.1%.
- Fixed a boundary condition in `select_strategy()` (`partial_rate <= 0.1`).

## 0.5.1 — 2026-04

- Attacker: auditor framing in the system prompt, three-tier retry when the
  attacking model refuses, self-censorship detection (15 patterns, ES and EN),
  Jaccard anti-repetition between consecutive prompts.
- Three multi-turn strategies: gaslighting, context_overflow, persona_persistence.
- Corpus to 39 validated seeds across 19 RAG vectors plus 11 agentic vectors.
- Token accounting, early termination after three consecutive refusals, and a
  persistent evaluation cache for low scores.

## 0.4.0 and earlier

Single-shot campaigns against a local RAG target, LLM-as-judge scoring, the first
mutation strategies, and the SQLite result store.
