#!/usr/bin/env python3
"""Migrate the corpus to the 2026 OWASP taxonomies.

Two lists were renumbered in 2026 and the corpus was written against the old ones:

  * OWASP GenAI LLM Top 10 2026 (published 3 August 2026). Most entries moved.
    LLM07 System Prompt Leakage became LLM08 Hidden Context Exposure; LLM07 is now
    Misinformation. Model Theft no longer exists.
  * OWASP Top 10 for Agentic Applications 2026. The corpus used a four-item draft
    where ASI04 meant "excessive agency". In the published list ASI04 is Agentic
    Supply Chain Compromise, and ASI06/ASI07 (memory poisoning, inter-agent
    communication) exist for the first time.

This script is the whole migration, not part of it: run it against a pre-2026
corpus and you get the shipped one back, byte for byte. It rewrites `owasp` and
`category` on the RAG seeds, and `owasp_agentic` plus the seed `id` on the agentic
ones. It is idempotent.

Agentic IDs used to encode the ASI number (AGT-ASI01-001). That number gets
reassigned every time OWASP revises the list, so the ID ends up lying about the
seed. They are sequential now.

    python scripts/remap_owasp_2026.py [seeds_dir]

Writes a .pre2026 backup next to each file it touches.
"""
import json
import shutil
import sys
from pathlib import Path

# vector -> (2026 category id, snake_case category name)
# The category string is what reports and the attacker prompt read, so leaving it
# on the 2023 names would have seeds labelled "training_data_poisoning" sitting
# under a category that is explicitly about extraction, not poisoning.
RAG = {
    "V01_numerical_anchor":          ("LLM02", "sensitive_information_disclosure"),
    "V02_summary_exfiltration":      ("LLM02", "sensitive_information_disclosure"),
    "V03_temporal_fragmentation":    ("LLM02", "sensitive_information_disclosure"),
    "V04_inverse_negation":          ("LLM08", "hidden_context_exposure"),
    "V05_passive_context_leak":      ("LLM09", "vector_and_embedding_weaknesses"),
    "V06_role_impersonation":        ("LLM01", "prompt_injection"),
    "V07_cross_language_confusion":  ("LLM01", "prompt_injection"),
    "V08_chain_of_thought_exploit":  ("LLM02", "sensitive_information_disclosure"),
    "V09_compliant_reformulation":   ("LLM02", "sensitive_information_disclosure"),
    "V10_indirect_prompt_injection": ("LLM01", "prompt_injection"),
    "V11_social_engineering":        ("LLM01", "prompt_injection"),
    "V12_training_data_extraction":  ("LLM08", "hidden_context_exposure"),
    "V13_resource_exhaustion":       ("LLM06", "unbounded_consumption"),
    "V14_context_window_exploit":    ("LLM02", "sensitive_information_disclosure"),
    "V15_excessive_agency":          ("LLM03", "excessive_agency"),
    "V16_compound_jailbreak":        ("LLM01", "prompt_injection"),
    "V17_output_manipulation":       ("LLM10", "improper_output_handling"),
    "V18_supply_chain_trust":        ("LLM04", "supply_chain"),
    "V19_model_extraction":          ("LLM06", "unbounded_consumption"),
}

AGENTIC = {
    "goal_hijacking":                  ("ASI01", "agent_goal_hijack"),
    "indirect_prompt_injection":       ("ASI01", "agent_goal_hijack"),
    "tool_misuse":                     ("ASI02", "tool_misuse_and_exploitation"),
    "data_exfiltration_chain":         ("ASI02", "tool_misuse_and_exploitation"),
    "excessive_agency":                ("ASI02", "tool_misuse_and_exploitation"),
    "privilege_escalation":            ("ASI03", "agent_identity_and_privilege_abuse"),
    "cross_tool_privilege_escalation": ("ASI03", "agent_identity_and_privilege_abuse"),
    "gradual_permission_escalation":   ("ASI03", "agent_identity_and_privilege_abuse"),
    "feature_flag_abuse":              ("ASI03", "agent_identity_and_privilege_abuse"),
    "memory_poisoning":                ("ASI06", "memory_and_context_poisoning"),
    "cross_agent_injection":           ("ASI07", "insecure_inter_agent_communication"),
}

# Fields the pre-2026 corpus never had and nothing reads. Dropped if present so a
# re-run cannot leave half-migrated leftovers behind.
DEAD_FIELDS = ("owasp_secondary", "legacy_id")


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path, seeds):
    path.write_text(json.dumps(seeds, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(root):
    unknown = set()
    changed = 0

    for name in ("seeds_validated.json", "seeds_mutated.json"):
        path = root / name
        if not path.exists():
            continue
        shutil.copy(path, path.with_suffix(".json.pre2026"))
        seeds = load(path)
        for s in seeds:
            mapping = RAG.get(s["vector"])
            if mapping is None:
                unknown.add(s["vector"])
                continue
            owasp, category = mapping
            changed += (s.get("owasp"), s.get("category")) != (owasp, category)
            s["owasp"], s["category"] = owasp, category
            for dead in DEAD_FIELDS:
                s.pop(dead, None)
        save(path, seeds)
        print(f"{name}: {len(seeds)} seeds")

    path = root / "agent_seeds.json"
    shutil.copy(path, path.with_suffix(".json.pre2026"))
    seeds = load(path)
    for i, s in enumerate(seeds, 1):
        mapping = AGENTIC.get(s["vector"])
        if mapping is None:
            unknown.add(s["vector"])
            continue
        owasp, category = mapping
        new_id = f"AGT-{i:03d}"
        changed += (s.get("owasp_agentic"), s.get("category"), s.get("id")) != (owasp, category, new_id)
        s["owasp_agentic"], s["category"], s["id"] = owasp, category, new_id
        for dead in DEAD_FIELDS:
            s.pop(dead, None)
    save(path, seeds)
    print(f"agent_seeds.json: {len(seeds)} seeds")
    print(f"seeds rewritten: {changed}")

    if unknown:
        print(f"\nERROR: no 2026 mapping for {sorted(unknown)}", file=sys.stderr)
        print("Add them to RAG or AGENTIC above. Leaving a vector on its old ID "
              "silently is how the corpus drifted in the first place.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "vigia/corpus/seeds")))
