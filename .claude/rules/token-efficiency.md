# Token Efficiency Rules (always loaded)

- Bash output: always pipe through `| head -50` unless full output explicitly needed
- Never dump entire files into context. Use grep/awk to extract relevant sections.
- Responses: code and data only, no explanations unless asked
- If a task has >3 steps, use subagents for exploration, keep main context clean
- After 2 failed corrections on same issue: stop, reassess, start fresh prompt
- When referencing files, use @ syntax instead of reading entire files
- Compact with guidance: "/compact focus on [current task]"
