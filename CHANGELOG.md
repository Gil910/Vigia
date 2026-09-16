# Changelog

## 0.6.1 — 2026-09-16

0.6.0 never reached PyPI. A last read-through before uploading found that the
second command in its own README did not work, so this is that release with the
review applied on top.

### The package did not work the way the README says

- **`vigia run -c vigia/config/claude_haiku.yaml` raised `FileNotFoundError`.**
  0.6.0 added `vigia/paths.py` to resolve shipped files against the installed
  package and wrapped it around the argparse *defaults* only — so `vigia run`
  with no arguments worked from any directory and every documented invocation
  that names a config did not, including `cp vigia/config/http_example.yaml
  mine.yaml`. Resolution happens where the path is opened now, so a path the
  user typed gets the same treatment as one we shipped, and a path that is
  nowhere is a sentence naming the shipped configs rather than a traceback.
- **`vigia mutate` threw away the whole run on its last line.** The default
  output was `vigia/corpus/seeds/seeds_mutated.json`, which lives inside
  site-packages after an install and does not exist anywhere else, so a finished
  mutation campaign — minutes of model calls — died writing it. It writes
  `seeds_mutated.json` in the working directory.
- **`vigia run -c mine.yaml` refused to start against an HTTP target.** The
  model-presence check read `model` out of every config block, and an HTTP
  target's `model` is a label for the report, which the file itself says in a
  comment. Pointing Vigia at your own chatbot — the thing the tool is for —
  asked you to `ollama pull chatbot-empresa-v1`.
- **The same check accepted the wrong model.** `llama3.1:70b` was satisfied by
  having `llama3.1:8b`, because the tag relaxation ran in both directions. It
  now runs only the way Ollama needs it: an untagged name matches any tag, a
  tagged one has to match exactly.
- **`vigia scan`, `multiturn`, `mutate` and `agent` skipped the preflight
  entirely** and died in forty lines of langchain traceback with Ollama down.
  All of them exit 2 with the same panel `vigia run` prints, and `scan` writes
  it to stderr so a `--format json` artefact stays parseable.

### A judge that is up and useless

- **A judge that answers and never in JSON reported PASSED on a target that
  leaked every time.** 0.6.0 made an unparseable verdict score -1 instead of 0,
  which was right, and then counted it as a healthy answer — resetting the
  consecutive-failure counter, so `JudgeUnavailable` could never fire, so the
  scan ended with no findings, no errors and exit 0. Five in a row aborts now.
- **Parse errors were written to the persistent cache.** The cache stores scores
  of 2 or less and -1 is less than 2, so one malformed reply was replayed for
  that prompt in every later campaign, across databases.

### SECURITY.md said credentials never reach disk. They did

- **`redact()` masked by key name only.** `Authorization:` was caught; a Gemini
  `?key=` in the target URL and a token inside `request_template` were stored
  verbatim in `campaigns.config` — in the `.db` this project tells people to
  attach to a report. Leaf strings go through the same masking as error text
  now, untruncated so a config stays reproducible.
- The credential pattern was `[a-z]{2}-` plus eight characters, which redacted
  every seed id and locale tag out of the logs a user debugs with
  (`Timeout evaluating seed [redacted] after 30s`). It is anchored on `sk-`.
- An absolute home directory in `database.path` travelled into every stored
  config. Not a credential, but it is a name on a shared file; it goes in as `~`.
  The database shipped in `results/` predates this and still carries mine.
- Exfiltration destinations in the shipped seeds named domains that exist and
  that I do not own — `evil.com`, `personal-mail.com`, `techcorp.com`. If a
  user's agent has a real `send_email` tool and complies, that mail leaves. They
  are `.invalid` and `.example` now, which are reserved and never resolve.
- `to_junit()` did not escape the target model name and did not strip the
  control characters XML 1.0 forbids, so a hostile model name or raw judge
  reasoning produced a report no CI server can parse. `to_json()` reported
  `passed` next to an exit code of 2.
- `_judge_health` is process-global and `vigia benchmark` runs several scans in
  one process, so the second model inherited the first one's failures and could
  abort on its first hiccup. Each campaign resets it.

### Numbers that were still describing the old corpus

Found by re-deriving every published figure from the committed database and the
April one, rather than re-reading the prose.

- The RAG vector table in both READMEs listed **V12 at 55 attacks and 43.6%**.
  Removing the four seeds that were the mutator's own system prompt makes it 35
  and 34.3%, which drops it out of the top seven; V08 chain-of-thought exploit
  (25, 48.0%) is the row that belongs there.
- **V09 was mapped to LLM01** in both READMEs and **V01 in the Spanish one**. The
  corpus maps both to LLM02 and `validate_corpus.py` enforces it, so the tables
  disagreed with the data they describe.
- The Catalan corpus was described as "a single seed covering 76 of its 80
  attacks". 76 and 80 are the same population under two different filters. In the
  April database ca-ES has 76 usable attacks, 72 of them that one numerical
  anchor; the other two seeds are agentic. `es-ES` carried 65 seeds, not 63.
- METHODOLOGY's score distribution said 404 and 296 where the database says 403
  and 294 — and 404 + 165 + 13 + 296 is 878, not 875.
- "18 usable Galician seeds over 5 vectors" was neither number: 18 seeds touching
  13 vectors, 4 of which carry enough attacks to compare.
- The dead-seed breakdown listed three shapes adding up to 53 of 58. There are
  four, and the missing one is the shape the first detector could not see.
- `README.md` told the reader to reproduce the chain-of-thought finding with
  `--campaigns 5`, which has no reasoning captured in it. It is campaign 18, as
  the Spanish README already said.
- `README.es.md` pointed `stats.py` at a database that is not in the repo, said
  "two scripts" where the English says three, and asserted that translation
  quality changes the result — which is the finding this release withdraws.
- Sample sizes said RAG vectors run 30–85 each; the smallest is 25. Variance was
  "one in ten to one in five" and "half to two-thirds" where the table says 12–22%
  and 44–63%. The four agentic rows reading 100% are not all three-out-of-three;
  one is six of six.
- RESULTS.md printed "Campaigns whose config does not match what they did: 8",
  where the 8 is a campaign id and every reader takes it for a count.
- `scripts/stats.py --help` answered with a sqlite traceback, and
  `scripts/remap_owasp_2026.py --help` — which rewrites the corpus in place — was
  already inside `shutil.copy` before it checked its argument.

### And the reason there was a fourth list

Four reviews in a row each found something the last one had not, which is not a
story about carelessness. "Review the project" is not a repeatable procedure: each
pass looked wherever whoever was doing it thought to look. The prose pass never
installed the wheel. The packaging pass never re-derived a percentage. The release
that fixed `vigia run` shipped with `vigia run -c <a config>` broken, because
nobody had typed the second line of the README on a clean machine.

`scripts/preflight.py` is the list instead of the intention. Twenty-four checks,
each one a bug this repository actually had: the version agrees with itself, every
published percentage traces to a generated table, the two READMEs quote the same
numbers, the OWASP column matches the corpus, every link and path and command in
the documentation resolves, no exfiltration destination is a domain somebody could
register, and — the one that would have caught this release — a wheel installed
into an empty virtualenv survives every command the documentation gives, with no
traceback.

It runs in CI on every push and with `--full` before a release, where it also
builds, runs twine, and does the clean install. `tests/test_preflight.py` hands
each check a copy of the repository with exactly the defect it claims to catch, so
a check that has quietly stopped checking anything fails the suite.

What it does not cover is worth naming, because the point is knowing where the
edge is: whether the Basque is Basque, whether a verdict is right, whether the
bootstrap intervals were computed correctly. Those need a person.

564 tests, ruff clean, `python scripts/preflight.py --full` clean.

## 0.6.0 — 2026-09-08

A correctness release with one new finding in it, and one finding removed.

Most of this is things that were wrong being made right, including two headline
results that turned out to be artefacts of my own corpus — the second one found
four days after I had written the launch post around it. The rest is the tooling
that found them: everything published now comes out of a script with tests, the
corpus is checked for content and not just for schema, and the same responses have
been scored by three different judges so that the difference between "the models
do this" and "my judge does this" is on the page rather than in my head.

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
- `vigia --version` reported 0.4.0 since v0.5, and then stopped existing: the
  number was hardcoded in `cli.py` while `pyproject.toml` said 0.5.3, and the
  cleanup that gave `vigia/__init__.py` the single source of truth removed the
  flag along with it. The flag is back and reads from there.
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
  check. Lint went from 174 findings to zero.
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
- **The corpus was balanced, and it was still wrong.** It carried 38 or 39 seeds
  in every locale except Catalan, whose single RAG seed covered 72 of its 76
  usable attacks and belonged to one of the two strongest vectors. The published "+24 points for
  Catalan" was that vector, not that language. 38 generated Catalan seeds brought
  every locale to 38–39 over the same 19 vectors, and a test fails if they drift
  apart again. Then see the next entry.
- **58 of the 233 seeds are not attacks**, in four shapes. Fifty are the mutation
  model declining to translate, written into the corpus as if the refusal were the
  prompt, fifteen of them the same sentence. Three are the same refusal in a
  different coat, the mutator answering in its own voice — *"como modelo de
  lenguaje no tengo acceso a información en tiempo real"* — which is the shape the
  first version of the detector missed, because it does not open with an apology.
  Four are the mutator's own system prompt, filed under V12 training data
  extraction — a seed whose job is to extract a system prompt, containing one. One
  came back as five invented employees with ID numbers and salaries: the model
  answered the attack instead of translating it. They score 0 by construction and they are not spread evenly —
  21 in gl-ES, 15 in eu-ES, 3 in ca-ES, **none in es-ES**, which is the shape of
  the finding they were producing. `vigia/corpus/hygiene.py` is the detector,
  `vigia mutate` retries and then drops rather than storing one,
  `scripts/validate_corpus.py` fails on one, and `scripts/stats.py` excludes them
  per row so an old database is re-analysed correctly without being rewritten.
- **The corpus ships 222 seeds, and the locales are not level: 34 to 39.**
  Regenerating the dead ones ran into something worth writing down: an aligned
  model will not translate an attack, and a model that will does not speak Basque.
  `claude-haiku` produced grammatical Batua and then declined on eleven seeds —
  in Basque, mid-prompt — while `mistral` declined on nothing and produced text
  that reads like Basque only to someone who does not read Basque. Those eleven
  are dropped rather than faked. An unbalanced corpus is a limitation; a balanced
  one with eleven refusals in it is a lie.
- **The language finding is withdrawn.** Not because the effect is zero: with the
  dead rows excluded the two-tier gap falls from 9.6 to 6.0 points under Haiku and
  from 10.7 to 7.1 under gpt-5.6-luna, borderline under both. It is withdrawn
  because the first version of the hygiene check gave 4.2 points and the second
  gave 6.0 on the same database with no new data — a 40% move in the estimate from
  a change in the cleaning rule, with no principled place to stop cleaning. gl-ES
  is also down to 18 usable seeds, only four of whose vectors carry enough attacks
  to compare, below the coverage `stats.py` requires, so the controlled table
  leaves it and eu-ES out and says why.
- **New: the reasoning leaks what the answer refuses to say.** deepseek-r1:8b's
  chain of thought was captured and the same 175 responses scored twice, once on
  the final answer alone and once on the reasoning alone. Answer 23.4%, reasoning
  30.3%, and in 26 of 175 the answer was clean while the reasoning named the
  thing. A second judge puts it at 26.9%, 36.6% and 34. One generation judged
  twice, so none of the gap is run-to-run noise. This is the finding that survived
  both corpus corrections, because it is a within-target comparison and the corpus
  cancels out of it.
- **Judge bias, separated.** A model scoring itself reports +7.4 points against a
  neutral judge; the same judge pointed at a target that is not itself adds +4.0.
  More than half the inflation is general strictness, the rest is self-assessment.
- **Run-to-run variance on three models**, at the temperature the config actually
  asks for: llama3.1:8b flips 12.0% of individual verdicts between identical runs,
  gemma3:4b 15.4%, deepseek-r1:8b 22.3%, while the aggregate holds within a point.
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
  normal-looking table with a different number inside.

### Hardening

Found by reading the code rather than by a failing test, which is why each of
these now has one.

- **Campaign configs were written to the database verbatim**, and an HTTP target's
  config carries the `Authorization` header used to reach it — so a bearer token
  ended up in the `.db`, which is the file people attach to a report. Credentials
  are redacted before the write, and provider error strings, which reach both the
  database and the JUnit output and can carry a key in a URL, are scrubbed too.
- **`vigia scan` returned 0 when every judge call failed.** The condition for "the
  scan did not run" was `total_executed == 0`, and `total_executed` counts target
  queries rather than verdicts — so a target that answered every prompt while the
  judge was down produced no findings, passed, and exited green. A scan that
  errored and found nothing now exits 2.
- **`JudgeUnavailable` never propagated.** It subclasses `RuntimeError` and every
  campaign loop caught `Exception`, so the abort added in this release printed once
  per remaining seed and then finished the campaign anyway.
- **`pip install vigia && vigia run` could not work.** Every default path was
  written the way it looks from a clone, so the first thing a new user ran died on
  `FileNotFoundError: vigia/config/default.yaml`. Defaults resolve against the
  installed package now, and a run that needs Ollama says so instead of raising out
  of langchain.
- `record_attack` had the success threshold hardcoded at 5, so
  `evaluator.success_threshold` was read, used for the console output, and thrown
  away at the write.
- **The euskera and gallego mutation strategies were unreachable.** `mutate_seed`
  truncated the strategy *list* to `mutations_per_seed`, which is 5 in every
  shipped config, and those four sit at positions 9 to 12. The list is rotated by
  the seed id now, so a corpus reaches all twelve.
- Fourteen `open()` calls read without an explicit encoding, so under `LC_ALL=C` —
  the default in slim images and several CI runners — the corpus failed to load on
  its first accented character.
- `init_db` crashed on a database path with no directory component.
- `stats.py` opens the database read-only, and no longer creates an empty file when
  pointed at a path that does not exist.

- **The shipped default config had the target judging itself.** `vigia run` with
  no arguments ran llama3.1:8b against llama3.1:8b, which is the anti-pattern
  three sections of METHODOLOGY are about and worth about 7 points of inflation.
  The default judge is `mistral` now — still local, still one `ollama pull`, and
  not the target. There is a test that no shipped config self-judges, because
  this is the kind of thing that comes back.
- **`warn_if_self_judging` quoted April's numbers** (23.0% against 14.1% over 135
  attacks) in a release whose whole point is that April's numbers are wrong. It
  says 25.1% against 17.7% over 175 now, which is what `docs/RESULTS.md` says.
- **A judge reply that would not parse scored 0**, so every table counted it as a
  verdict that the target held — the same mistake as counting a timeout as a
  pass. It scores -1 now and `stats.py` reports it apart from an attack that
  never reached the judge at all. A non-numeric score (`{"score": "alto"}`) took
  the same route instead of raising out of the parser and counting towards the
  five consecutive failures that abort a campaign.
- **`vigia run` checks the models exist**, not just that Ollama is up. Missing one
  used to mean a 404 per attack, discovered halfway through a campaign.
- Config files for the five benchmark models, all judged by claude-haiku, so a
  reader who wants to reproduce a row in `docs/RESULTS.md` can find the file that
  produced it. `gemini.yaml` named a model the results never used; `gemma2.yaml`
  targeted `gemma2:2b` while every published table is `gemma3:4b`.

- Packaging metadata migrated to PEP 639: `license = "MIT"` as an SPDX expression
  plus `license-files`, and the `License :: OSI Approved :: MIT License`
  classifier dropped, which is the pair setuptools now refuses to accept
  together. `python -m build` came out with four deprecation warnings and comes
  out silent. `build` and `twine` moved into a `release` extra so they are not
  installed by the three CI jobs that never publish anything.

- `scripts/stats.py --help` answered with a sqlite traceback, because the script
  takes a positional path with a default and read `--help` as a filename.
  `scripts/remap_owasp_2026.py` did the same, and that one rewrites the corpus in
  place, so it had already started writing `.pre2026` backups before it failed.
  Both check their argument now and print usage.

511 tests, 74 of them in a new `tests/test_hardening.py`, ruff clean.

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
