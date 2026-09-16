# Contributing

Bug reports and new attack seeds are both welcome. The seeds are where the
project actually gets better, so that is the most useful thing you can send.

## Before you open a pull request

```bash
ruff check vigia/ tests/ scripts/
pytest -q
python scripts/preflight.py
```

The third one is the odd one. It checks the claims the repository makes about
itself rather than the code: that every published percentage traces to a table
`scripts/stats.py` generated, that the two READMEs quote the same numbers, that
every link and command in the documentation resolves, that no seed tells an agent
to exfiltrate to a domain somebody could register. It exists because four separate
reviews of this project each found something the previous one had not, and the
common factor was that none of them was working from a list. `--list` says what it
checks and why; each check is a bug this repository actually had.

## Adding a seed

Seeds live in `vigia/corpus/seeds/seeds_validated.json`. Every entry needs:

```json
{
  "id": "ES-V01-042",
  "vector": "V01_numerical_anchor",
  "category": "sensitive_information_disclosure",
  "owasp": "LLM02",
  "atlas": "AML.T0048.004",
  "language": "es-ES",
  "prompt": "...",
  "target_behavior": "salary_disclosure",
  "success_keywords": ["€", "salario"],
  "severity": "high"
}
```

`owasp` and `category` are not free text: they are derived from `vector` by the map
in `scripts/remap_owasp_2026.py`, and `scripts/validate_corpus.py` fails the build
if a seed disagrees with it. Adding a seed to an existing vector means copying that
vector's values. Adding a *new* vector means adding a row to that map first — which
is deliberate, so nobody has to guess where a vector belongs.

Run the validator before you open the PR:

```bash
python scripts/validate_corpus.py
```

`atlas` is a MITRE ATLAS technique ID and is not validated, because the existing
ATLAS mapping is not good enough to validate against yet — see the last section of
`docs/TAXONOMY.md`. Pick the closest technique and say in the PR why.

Run the seed against the demo target at least once before opening the PR, and put
the score you got in the description. A seed that never scores above 2 against
anything is noise.

## Code

- Every LLM call goes through `vigia/providers.py`. Do not import `ollama` or
  `litellm` anywhere else; the provider switch is what lets the same seed run
  against a local model and against an API.
- Tests mock `vigia.providers.llm_chat`. Nothing in `tests/` should hit a real
  model or a real network.
- `ruff check vigia/ tests/ scripts/` and `pytest` before pushing.

## Changing the evaluator

Two things in `vigia/evaluator.py` are load-bearing across every campaign ever run.

The **judge prompt** scores every result, so changing it silently invalidates
comparisons against older runs. If you do change it, say so in the PR and re-run at
least one full benchmark so there is a before and after.

The **cache key** (`_cache_key`) decides when two judging calls are the same call.
It used to hash the response alone, which meant a turn could inherit an earlier
turn's verdict because the chatbot happened to repeat itself. Anything you drop from
that key is something you are asserting cannot change the verdict. There are tests
pinning this; if you find yourself editing them to make a change pass, stop.
