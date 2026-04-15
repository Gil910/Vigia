# VIGÍA — LLM Red Teaming Framework

## Commands
- `source venv/bin/activate && pytest tests/ -v` — run tests
- `ruff check vigia/` — lint
- `vigia run` — default campaign (llama3.1:8b target)
- `vigia run -c vigia/config/claude_haiku.yaml` — campaign vs Claude
- `vigia agent --plan` — auto-generate attack plan + run against agent
- `vigia scan --fail-on-score 5` — CI/CD gate mode
- `vigia benchmark -c vigia/config/*.yaml` — cross-model comparison
- `vigia mutate --strategies euskera,gallego,codeswitching_euskera` — generate variants
- `vigia multiturn --strategy rapport_to_extraction --max-seeds 3` — multi-turn

## Architecture
- `vigia/cli.py` — CLI entry point (Rich tables, welcome screen)
- `vigia/attacker.py` — single-shot attack execution
- `vigia/evaluator.py` — LLM-as-judge scoring (0-10)
- `vigia/mutation_engine.py` — 12 linguistic mutation strategies (es, ca, eu, gl + codeswitching)
- `vigia/scanner.py` — CI/CD gate mode (ScanResult, JUnit XML, JSON output)
- `vigia/benchmark.py` — cross-model comparison (BenchmarkResult, table/markdown/JSON)
- `vigia/providers.py` — Ollama + LiteLLM abstraction
- `vigia/database.py` — SQLite results storage
- `vigia/reporting/generator.py` — report generation
- `vigia/agents/` — agentic attack pipeline:
  - `planner.py` — attack surface analysis → plan generation
  - `runner.py` — multi-turn attack execution
  - `target.py` — target agent wrapper
  - `tools.py` — tool definitions + permission model
  - `evaluator.py` — agentic evaluator
  - `remediation.py` — fix recommendations
- `vigia/targets/` — victim chatbot (RAG + ChromaDB)
- `vigia/corpus/seeds/` — attack seeds (JSON): 19 RAG + 18 agent + 44 mutated
- `vigia/config/` — YAML configs per model

## Conventions
- Python 3.11+. Type hints on all function signatures.
- All LLM calls go through `providers.py` (llm_chat/parse_json_response). Never call ollama/litellm directly.
- Attack seeds follow the JSON schema: id, vector, category, owasp/owasp_agentic, language, prompt, target_behavior, severity
- OWASP mapping: LLM01-LLM10 for RAG attacks, ASI01-ASI04 for agentic attacks
- Language codes: es-ES, ca-ES, eu-ES, gl-ES, es-CA, es-EU, es-GL
- MITRE ATLAS IDs where applicable
- Tests use pytest. Mock LLM calls, never hit real APIs in tests.
- Output bash: always `| head -50`

## Watch out
- venv is at `./venv/` — always activate before running
- ChromaDB needs `nomic-embed-text` pulled in Ollama first
- `providers.py` handles both ollama and litellm — provider param determines routing
- Seeds JSON files are the source of truth for attack corpus. Never modify programmatically without backup.
- The evaluator prompt is critical — changes affect all scoring. Test with known TP/FP pairs before modifying.
