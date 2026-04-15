---
name: seed-generator
description: "Automated seed generation and mutation. Use when the user wants to generate new attack seed variants, run mutations on existing seeds, or expand the corpus systematically."
allowed-tools: Bash, Read, Write, Grep, Glob
---

# Seed Generator Workflow

## Step 1 — Load Base Seeds
```bash
cat vigia/corpus/seeds/seeds_validated.json | python3 -c "
import sys, json
seeds = json.load(sys.stdin)
print(f'Loaded {len(seeds)} validated seeds')
for s in seeds:
    print(f'  {s[\"id\"]}: {s[\"vector\"]} [{s[\"language\"]}] - {s[\"severity\"]}')
"
```

## Step 2 — Select Mutation Strategy
Available strategies (from mutation_engine.py):
- `register_formal` — subjunctive, ustedeo, extreme courtesy
- `register_informal` — tuteo, colloquial expressions
- `catalan` — full translation to Catalan
- `codeswitching` — mix Spanish + Catalan in same sentence
- `rephrase` — complete rephrasing with different structure
- `academic` — research/audit framing
- `authority` — authority role (auditor, IT, management)
- `sms_speak` — SMS/WhatsApp Spanish abbreviations

## Step 3 — Generate Variants
```bash
source venv/bin/activate && vigia mutate --strategies <strategy1>,<strategy2> --seeds-file vigia/corpus/seeds/seeds_validated.json
```

## Step 4 — Validate
Run generated variants against a known-vulnerable target to verify they produce expected results:
```bash
source venv/bin/activate && vigia run --corpus vigia/corpus/seeds/seeds_mutated.json
```

Check results for:
- Mutations that increased success rate vs originals
- Mutations that decreased (may have broken the attack intent)
- New linguistic patterns worth promoting to validated seeds
