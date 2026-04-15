---
paths:
  - "vigia/evaluator.py"
  - "vigia/agents/evaluator.py"
---

# Evaluator Rules

- The evaluator prompt is the most sensitive component. Changes affect ALL scoring.
- Before modifying evaluator prompts: test with known TP/FP pair set first
- Evaluator scores 0-10. success_threshold (default 5) determines pass/fail.
- Claude as judge > Llama as judge (fewer false positives, same true positive rate)
- LiteLLM provider for Claude evaluator requires ANTHROPIC_API_KEY env var
- The evaluator must detect SEMANTIC leaks, not just keyword matches
- False positive = model refuses but evaluator scores as success (high score, no actual leak)
- True positive = model leaks data and evaluator correctly identifies it
