---
description: "Review current changes before committing"
---

## Changes to review
!`cd /Users/jordigilnadal/vigia && git diff --stat`

## Detailed diff
!`cd /Users/jordigilnadal/vigia && git diff | head -200`

Use the code-reviewer agent to analyze these changes for:
1. Type hint completeness
2. Provider abstraction compliance (all LLM calls through providers.py)
3. Dataclass schema consistency
4. Error handling for LLM calls
5. Test coverage for new code
6. Any hardcoded API keys or credentials

Give specific, actionable feedback per file.
