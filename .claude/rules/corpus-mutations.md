---
paths:
  - "vigia/corpus/**"
  - "vigia/mutation_engine.py"
  - "vigia/mutation/**"
---

# Corpus & Mutation Rules

- Seeds JSON is source of truth. ALWAYS backup before programmatic modification.
- Seed schema: { id, vector, category, owasp_agentic, language, prompt, target_behavior, severity }
- Language codes: es-ES (castellano), ca-ES (catalán), es-CA (codeswitching es-ca), eu-ES (euskera), es-EU (codeswitching es-eu), gl-ES (gallego), es-GL (codeswitching es-gl)
- 12 mutation strategies: register_formal, register_informal, catalan, codeswitching, euskera, codeswitching_euskera, gallego, codeswitching_gallego, rephrase, academic, authority, sms_speak
- Mutations must preserve: attack intent, target_behavior, severity, owasp mapping
- New seeds need validation: run against known-vulnerable target, confirm scoring
- seeds_validated.json = manually verified seeds. seeds_mutated.json = machine-generated.
