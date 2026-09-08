#!/usr/bin/env python3
"""Regenerate the corpus seeds that are not attacks.

`scripts/validate_corpus.py` fails on a seed that is the mutation model
declining rather than rewriting. This regenerates exactly those, from the same
parent seed and the same strategy, and writes them back.

    python scripts/fix_seeds.py --list
    python scripts/fix_seeds.py --model mistral

Pick a different model from the one that produced the corpus. The seeds that
need fixing are the ones llama3.1:8b refused, and asking it again mostly gets
the same refusal — `mistral` and `qwen3:8b` both decline far less on this
corpus. Everything else about the seed is left alone: only `prompt` changes.
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from vigia.corpus.hygiene import degenerate_reason  # noqa: E402
from vigia.mutation_engine import STRATEGIES, MutationEngine  # noqa: E402

CORPUS = ROOT / "vigia/corpus/seeds/seeds_validated.json"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--model", default="mistral",
                    help="mutation model (default: mistral)")
    ap.add_argument("--provider", default="ollama")
    ap.add_argument("--list", action="store_true",
                    help="name the seeds that need regenerating and stop")
    ap.add_argument("--limit", type=int, default=None,
                    help="only fix this many, for a quick check")
    args = ap.parse_args()

    path = Path(args.corpus)
    seeds = json.loads(path.read_text(encoding="utf-8"))
    by_id = {s["id"]: s for s in seeds}

    broken = [(s, degenerate_reason(s["prompt"])) for s in seeds]
    broken = [(s, why) for s, why in broken if why]

    if not broken:
        print(f"{len(seeds)} seeds, nothing to fix.")
        return 0

    print(f"{len(broken)} of {len(seeds)} seeds are not attacks:\n")
    for s, why in broken:
        print(f"  {s['id']:32} {s['language']:6} {s.get('mutation_strategy', '?'):22} {why}")
    print()

    if args.list:
        return 0

    todo = broken[:args.limit] if args.limit is not None else broken
    engine = MutationEngine(model=args.model, provider=args.provider)

    fixed, failed = [], []
    for i, (seed, _why) in enumerate(todo, 1):
        parent = by_id.get(seed.get("parent_id"))
        strategy = STRATEGIES.get(seed.get("mutation_strategy"))
        if parent is None or strategy is None:
            failed.append((seed, "no parent seed or unknown strategy — fix by hand"))
            continue

        print(f"[{i}/{len(todo)}] {seed['id']} via {seed['mutation_strategy']} "
              f"on {args.model}...", flush=True)
        new_prompt = engine._apply_strategy(parent["prompt"], strategy)

        if new_prompt is None:
            failed.append((seed, f"{args.model} would not rewrite it either"))
            continue
        seed["prompt"] = new_prompt
        seed["notes"] = (f"Mutación {seed['mutation_strategy']} de {parent['id']} "
                         f"(regenerada con {args.model})")
        fixed.append(seed)
        print(f"         {new_prompt[:100]}")

    if fixed:
        backup = path.with_suffix(".json.bak")
        if not backup.exists():
            shutil.copy(path, backup)
            print(f"\nBacked up to {backup.name}")
        path.write_text(json.dumps(seeds, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
        print(f"Rewrote {len(fixed)} seeds in {path.name}")

    if failed:
        print(f"\n{len(failed)} still need attention:")
        for seed, why in failed:
            print(f"  {seed['id']:32} {why}")
        print("\nTry another --model, or write those by hand. A seed that stays a")
        print("refusal will keep failing scripts/validate_corpus.py, which is the point.")
        return 1

    print("\nAll clear. Next:")
    print("  python scripts/validate_corpus.py")
    print("  python scripts/rerun.py            # the benchmark, on the fixed corpus")
    return 0


if __name__ == "__main__":
    sys.exit(main())
