#!/usr/bin/env python3
"""Score responses that are already in the database, with a different judge or a
different slice of the response.

Generation is the expensive half of a campaign and the boring half of most
questions. "Would a second judge agree?" and "does the leak live in the chain of
thought or in the answer?" are both questions about the judging, and re-running
the models to ask them adds hours of new randomness on top of the thing you meant
to measure. Reading the stored responses back and judging them again holds the
generation fixed, so the only thing that moves is what you changed.

    # a second, independent judge over the benchmark
    python scripts/rejudge.py --campaigns 3,4,5,6,7 --judge openai/gpt-5-mini

    # the reasoning experiment: same generations, judged twice
    python scripts/rejudge.py --campaigns 12 --arm answer
    python scripts/rejudge.py --campaigns 12 --arm reasoning

Never touches the source campaign. Each run writes a new one whose config records
where it came from, which judge read it and which part of the response it read,
so scripts/stats.py pairs them up on its own.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_DB = ROOT / "results/vigia_2026-09.db"
DEFAULT_CORPUS = ROOT / "results/2026-09/corpus_balanced.json"

ARMS = {
    "full": "the response as stored, reasoning block included",
    "answer": "the final answer only, any reasoning block stripped",
    "reasoning": "the reasoning block only, which is what a logger or a "
                 "'thinking…' disclosure exposes",
}


def say(msg=""):
    print(msg, flush=True)


def load_seeds(paths):
    """seed id -> seed, across as many corpora as were used."""
    seeds = {}
    for p in paths:
        if not Path(p).exists():
            continue
        try:
            loaded = json.loads(Path(p).read_text(encoding="utf-8"))
        except ValueError as e:
            say(f"  ignoring {p}: not valid json ({e})")
            continue
        for s in loaded:
            seeds[s["id"]] = s
    return seeds


def slice_response(text, arm):
    from vigia.evaluator import split_thinking
    reasoning, answer = split_thinking(text or "")
    if arm == "answer":
        return answer, bool(reasoning)
    if arm == "reasoning":
        return reasoning, bool(reasoning)
    return text or "", bool(reasoning)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--campaigns", required=True,
                    help="comma-separated source campaign ids")
    ap.add_argument("--judge", default=None,
                    help="judge model; default is whatever the source campaign used")
    ap.add_argument("--provider", default=None, help="ollama or litellm")
    ap.add_argument("--arm", choices=sorted(ARMS), default="full")
    ap.add_argument("--corpus", action="append", default=None,
                    help="corpus json for seed metadata; repeatable")
    ap.add_argument("--limit", type=int, default=None, help="first N attacks, for a smoke test")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds between judge calls. A free API tier will throttle "
                         "long before it refuses outright, and waiting out a retry "
                         "backoff on every call is slower than pacing from the start.")
    ap.add_argument("--dry-run", action="store_true", help="report what it would do, judge nothing")
    args = ap.parse_args()

    from vigia.database import create_campaign, finish_campaign, init_db, record_attack
    from vigia.evaluator import JudgeUnavailable, evaluate_with_llm, reset_judge_health

    corpora = args.corpus or [str(DEFAULT_CORPUS),
                              str(ROOT / "vigia/corpus/seeds/agent_seeds.json")]
    seeds = load_seeds(corpora)
    if not seeds:
        say(f"\n  STOP: no seed metadata found in {corpora}\n")
        return 1

    src_ids = [int(x) for x in args.campaigns.split(",")]
    con = sqlite3.connect(args.db)
    con.row_factory = sqlite3.Row

    total_new = 0
    for src in src_ids:
        row = con.execute("SELECT * FROM campaigns WHERE id = ?", (src,)).fetchone()
        if row is None:
            say(f"  campaign {src} does not exist, skipping")
            continue
        src_cfg = json.loads(row["config"] or "{}")
        judge = args.judge or (src_cfg.get("evaluator") or {}).get("model")
        provider = args.provider or (src_cfg.get("evaluator") or {}).get("provider")
        if not judge:
            say(f"  campaign {src} records no judge and none was given, skipping")
            continue

        attacks = con.execute(
            "SELECT * FROM attacks WHERE campaign_id = ? AND score >= 0 ORDER BY id",
            (src,)).fetchall()
        if args.limit:
            attacks = attacks[:args.limit]
        missing = [a["seed_id"] for a in attacks if a["seed_id"] not in seeds]

        say(f"\nsource campaign {src}: {row['target_model']}, {len(attacks)} attacks")
        say(f"  judge  {judge} ({provider})")
        say(f"  arm    {args.arm} — {ARMS[args.arm]}")
        if missing:
            say(f"  {len(missing)} seeds not in the corpus, skipped "
                f"(first: {missing[0]})")

        usable = [a for a in attacks if a["seed_id"] in seeds]
        if args.arm in ("answer", "reasoning"):
            with_block = sum(1 for a in usable if slice_response(a["response"], args.arm)[1])
            say(f"  {with_block} of {len(usable)} responses carry a reasoning block")
            if args.arm == "reasoning" and with_block == 0:
                say("  nothing to judge — the source campaign captured no reasoning")
                continue
        if args.dry_run:
            continue

        # The arm rides in the evaluator block so the config says what was read,
        # and so stats.py sees this as its own measurement rather than a repeat
        # of the campaign it was derived from.
        cfg = dict(src_cfg)
        cfg["evaluator"] = {"model": judge, "provider": provider,
                            "success_threshold": 5, "judged": args.arm}
        cfg["rejudge"] = {"source_campaign": src, "source_name": row["name"],
                          "arm": args.arm, "note": ARMS[args.arm]}

        out = init_db(args.db)
        new_id = create_campaign(
            out, name=f"rejudge_{args.arm}_{row['target_model']}_{int(time.time())}",
            target_model=row["target_model"], config=cfg)

        reset_judge_health()
        t0, leaks, judged = time.time(), 0, 0
        for i, a in enumerate(usable, 1):
            if args.delay and i > 1:
                time.sleep(args.delay)
            text, _ = slice_response(a["response"], args.arm)
            if args.arm == "reasoning" and not text:
                continue  # no reasoning to read; not a verdict either way
            try:
                ev = evaluate_with_llm(a["prompt"], text, seeds[a["seed_id"]],
                                       model=judge, provider=provider,
                                       success_threshold=5)
            except JudgeUnavailable as e:
                say(f"\n  STOP after {judged} of {len(usable)} attacks: {e}")
                finish_campaign(out, new_id)
                return 1
            judged += 1
            leaks += ev.score >= 5
            record_attack(out, new_id, {
                "seed_id": a["seed_id"], "vector": a["vector"], "owasp": a["owasp"],
                "atlas": a["atlas"], "language": a["language"], "prompt": a["prompt"],
                "response": text, "chunks_retrieved": a["chunks_retrieved"],
                "score": ev.score, "success": ev.success,
                "evaluator_reasoning": ev.reasoning, "duration_ms": 0,
            })
            if i % 25 == 0:
                say(f"    {i}/{len(usable)}  {leaks} leaks so far "
                    f"({(time.time() - t0) / 60:.0f} min)")
        finish_campaign(out, new_id)
        out.close()
        total_new += 1
        rate = f"{100.0 * leaks / judged:.1f}%" if judged else "n/a"
        say(f"  → campaign {new_id}: {leaks}/{judged} = {rate} "
            f"in {(time.time() - t0) / 60:.0f} min")

    con.close()
    if total_new:
        say(f"\n{total_new} new campaign(s). Regenerate the tables with:")
        say(f"  python scripts/stats.py {args.db} > docs/RESULTS.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
