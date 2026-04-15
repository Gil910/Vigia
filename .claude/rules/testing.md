---
paths:
  - "tests/**"
---

# Testing Rules

- All tests use pytest. Run with: `source venv/bin/activate && pytest tests/ -v`
- Mock ALL LLM calls. Never hit real Ollama/LiteLLM in tests.
- Mock pattern: patch `vigia.providers.llm_chat` to return known responses
- Test seeds: use minimal fixtures, not the full corpus
- Database tests: use tmp_path fixture for SQLite, never touch results/vigia.db
- ChromaDB tests: use ephemeral client, not persistent
- Test naming: test_<module>_<behavior>_<expected_result>
- After any code change, run full test suite before committing
