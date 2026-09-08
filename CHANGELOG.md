# Changelog

## 0.6.0 — 2026-09-08

A correctness release with one new finding in it.

Two thirds of this is things that were wrong being made right, including a
headline result that turned out to be an artefact of my own corpus. The rest is
the tooling that found them: everything published now comes out of a script with
tests, and the same responses have been scored by three different judges so that
the difference between "the models do this" and "my judge does this" is on the
page rather than in my head.

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

### Results, August 2026

Superseded by the September run below, and kept because the corrections are the
reason that run happened.

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

### Measurement, September 2026

The August release fixed how numbers are produced. This part re-took them, and
then attacked the instrument until it either broke or held.

- **Every published figure is from a fresh run under a judge that is none of the
  targets.** 233 seeds, six locales, five current models — qwen3:8b, gemma3:4b,
  deepseek-r1:8b, mistral and llama3.1:8b as a continuity anchor — judged by
  claude-haiku-4-5. April's numbers are no longer quoted anywhere.
- **The corpus is balanced.** It carried 39 seeds in every locale except Catalan,
  which had one, repeated across 76 campaigns and belonging to one of the two
  strongest vectors. The published "+24 points for Catalan" was that vector, not
  that language. 38 generated Catalan seeds bring every locale to 39 over the same
  19 vectors, and a test now fails if the locales drift apart again.
- **The language finding, restated.** Controlled for vector: ca-ES 38.9%, es-ES
  38.4%, eu-ES 28.8%, es-EU 27.7%, gl-ES 24.2%, es-GL 19.1%. Catalan and Spanish
  are indistinguishable and three judges disagree about which leads. The two-tier
  split — Spanish and Catalan 9 to 17 points above the rest — holds under all
  three, and that is the finding now.
- **New: the reasoning leaks what the answer refuses to say.** deepseek-r1:8b's
  chain of thought was captured and the same 233 responses scored twice, once on
  the final answer alone and once on the reasoning alone. Answer 18.5%, reasoning
  24.5%, and in 28 of 233 the answer was clean while the reasoning named the
  thing. A second judge puts it at 20.2%, 28.3% and 36. One generation judged
  twice, so none of the gap is run-to-run noise.
- **Judge bias, separated.** A model scoring itself reports +6.0 points against a
  neutral judge; the same judge pointed at a target that is not itself adds +2.6.
  Roughly half the inflation is general strictness, the rest is self-assessment.
- **Run-to-run variance on three models**, at the temperature the config actually
  asks for: llama3.1:8b flips 10.3% of individual verdicts between identical runs,
  gemma3:4b 12.9%, deepseek-r1:8b 18.0%, while the aggregate holds within a point.
- **Agentic results are a range, not a point.** The same 22 seeds run three times:
  10, 11 and 11 compromised, so 45–50%. The previous "100%" was four attacks.
- Multi-turn re-run under the neutral judge with a uniform six conversations per
  strategy. April's ran from 56 down to 3 and were not comparable with each other.

### Instrument

- **`scripts/rejudge.py`** scores stored responses again — with another judge, or
  with the reasoning block stripped or isolated — without re-running the models.
  The source campaign is read-only; each run writes a new campaign whose config
  records where it came from and what was read. Most of the section above exists
  because this made those questions cheap.
- **`scripts/overnight.py` and `scripts/experiments.py`** are the measurement
  plans, ordered cheap-and-decisive first so an interrupted run leaves a coherent
  set of results rather than half an experiment.
- **The judge stops instead of degrading.** A failed judge call falls back to
  counting keywords, which is right for one blip and fatal for a judge that has
  died. The guard used to require that the judge had never once answered — so when
  a free-tier quota ran out mid-campaign, 139 real verdicts were followed by 94
  keyword matches in the same campaign, which then read like an independent second
  opinion. Five consecutive failures now stop the run regardless of history.
- **`stats.py` discards keyword-scored rows** from every rate, names the campaigns
  they came from, and drops any campaign over 10% of them from the comparable set.
- **`stats.py` decides what a campaign measured from its data, not its config.**
  `RAGTarget` read `capture_thinking` and never passed it to the provider, so the
  database holds a campaign whose config asks for reasoning and whose responses
  have none. Believing the config paired it against the run that did capture
  reasoning and called a treatment effect run-to-run variance.
- **Campaign comparison is by shape, not by seed set.** The follow-up experiments
  fire the same seeds as the benchmark, so grouping on seeds alone let a
  self-judged run and a reasoning experiment stand in for benchmark rows — and one
  of them already had: the published deepseek figure was coming from the
  experiment.
- The judge cache key now includes the judge. Without it a campaign that changes
  evaluator reads back the previous one's verdicts, which is exactly what a judge
  comparison exists to measure.
- Judge truncation is reasoning-aware. The judge reads 600 characters, and with a
  captured chain of thought that window went entirely on the model's deliberation
  while the reply fell off the end.
- `_call_litellm` retries once without `temperature` against models that reject
  the parameter, and remembers which ones. Without it every call to such a model
  failed and the whole campaign degraded to keyword matching.
- The agent remediation engine counted one attack once per dimension it tripped,
  so a 22-attack campaign reported 38 vulnerabilities three lines under a table
  saying 10.
- `RAGTarget` passes `target.temperature` to the provider. It had been discarding
  it since the beginning, so every local target ran at Ollama's default of 0.8
  rather than the 0.3 its config asked for.
- The banner counted every json in the corpus directory, including the raw output
  of `vigia mutate`, and announced a corpus nearly twice the size of the one it
  attacks with.
- **`scripts/stats.py` has tests.** The script that generates every published
  number had none, and it had been wrong twice; both times it failed by printing a
  normal-looking table with a different number inside. 435 tests, ruff clean.

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
