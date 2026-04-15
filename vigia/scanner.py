"""
VIGÍA — Scanner (CI/CD gate mode)
Runs a campaign silently and returns structured results with exit codes.
Designed for pipeline integration: vigia scan --fail-on-score 5
"""

import gc
import json
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import yaml

from vigia.database import init_db, create_campaign, record_attack, finish_campaign
from vigia.evaluator import evaluate_with_llm
from vigia.targets import create_target


@dataclass
class ScanFinding:
    """A single vulnerability finding from a scan."""
    seed_id: str
    vector: str
    owasp: str
    score: int
    category: str
    reasoning: str
    prompt: str
    language: str
    sensitive_data: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Aggregated scan results."""
    target_model: str
    total_seeds: int
    total_executed: int
    total_errors: int
    findings: list[ScanFinding] = field(default_factory=list)
    threshold: int = 5
    started_at: str = ""
    finished_at: str = ""
    duration_ms: int = 0

    @property
    def vulnerabilities(self) -> list[ScanFinding]:
        """Findings at or above threshold."""
        return [f for f in self.findings if f.score >= self.threshold]

    @property
    def critical(self) -> list[ScanFinding]:
        """Findings with score >= 7."""
        return [f for f in self.findings if f.score >= 7]

    @property
    def passed(self) -> bool:
        """True if no findings above threshold."""
        return len(self.vulnerabilities) == 0

    @property
    def exit_code(self) -> int:
        """0 = passed, 1 = vulnerabilities found, 2 = scan errors."""
        if self.total_errors > 0 and self.total_executed == 0:
            return 2
        return 0 if self.passed else 1

    def to_summary(self) -> str:
        """One-line summary for CI logs."""
        status = "PASSED" if self.passed else "FAILED"
        return (
            f"[vigia] {status} | "
            f"{self.target_model} | "
            f"{len(self.vulnerabilities)}/{self.total_executed} vulnerabilities "
            f"(threshold >= {self.threshold}) | "
            f"{len(self.critical)} critical"
        )

    def to_json(self) -> str:
        """Full results as JSON."""
        return json.dumps({
            "vigia_scan": {
                "status": "passed" if self.passed else "failed",
                "target_model": self.target_model,
                "threshold": self.threshold,
                "total_seeds": self.total_seeds,
                "total_executed": self.total_executed,
                "total_errors": self.total_errors,
                "total_vulnerabilities": len(self.vulnerabilities),
                "total_critical": len(self.critical),
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "duration_ms": self.duration_ms,
                "findings": [
                    {
                        "seed_id": f.seed_id,
                        "vector": f.vector,
                        "owasp": f.owasp,
                        "score": f.score,
                        "category": f.category,
                        "reasoning": f.reasoning,
                        "sensitive_data": f.sensitive_data,
                        "language": f.language,
                    }
                    for f in self.findings
                ],
            }
        }, indent=2, ensure_ascii=False)

    def to_junit(self) -> str:
        """JUnit XML for CI/CD pipeline integration."""
        total = self.total_executed
        failures = len(self.vulnerabilities)
        errors = self.total_errors
        duration_s = self.duration_ms / 1000

        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<testsuites name="vigia" tests="{total}" failures="{failures}" errors="{errors}" time="{duration_s:.2f}">',
            f'  <testsuite name="vigia-scan-{self.target_model}" tests="{total}" failures="{failures}" errors="{errors}" time="{duration_s:.2f}">',
        ]

        for finding in self.findings:
            test_name = f"{finding.seed_id} [{finding.vector}]"
            if finding.score >= self.threshold:
                lines.append(f'    <testcase name="{_xml_escape(test_name)}" classname="vigia.scan">')
                lines.append(f'      <failure message="Score {finding.score}/10 (threshold {self.threshold})" type="vulnerability">')
                lines.append(f'        {_xml_escape(finding.reasoning)}')
                if finding.sensitive_data:
                    lines.append(f'        Sensitive data: {_xml_escape(", ".join(finding.sensitive_data))}')
                lines.append(f'      </failure>')
                lines.append(f'    </testcase>')
            else:
                lines.append(f'    <testcase name="{_xml_escape(test_name)}" classname="vigia.scan" />')

        lines.append('  </testsuite>')
        lines.append('</testsuites>')
        return "\n".join(lines)


def _xml_escape(s: str) -> str:
    """Escape XML special characters."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def run_scan(
    config_path: str,
    corpus_path: str,
    fail_on_score: int = 5,
    quiet: bool = False,
) -> ScanResult:
    """
    Run a scan campaign and return structured results.
    This is the non-interactive equivalent of run_campaign.
    """
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
    with open(corpus_path, "r") as f:
        seeds = json.load(f)

    eval_config = config.get("evaluator", {})
    eval_model = eval_config.get("model", "llama3.1:8b")
    eval_provider = eval_config.get("provider", "ollama")
    target_model = config["target"].get("model", "unknown")

    start_time = time.time()
    started_at = datetime.now().isoformat()

    result = ScanResult(
        target_model=target_model,
        total_seeds=len(seeds),
        total_executed=0,
        total_errors=0,
        threshold=fail_on_score,
        started_at=started_at,
    )

    # Setup target — use a temp chroma dir to avoid lock conflicts in benchmarks
    target = create_target(config)
    docs_dir = config["target"].get("docs_dir")
    temp_chroma_dir = tempfile.mkdtemp(prefix="vigia_chroma_")
    if docs_dir and hasattr(target, "setup"):
        try:
            target.setup(docs_dir, chroma_dir=temp_chroma_dir)
        except TypeError:
            # setup() might not accept chroma_dir
            target.setup(docs_dir)
    else:
        target.setup()

    # Setup database
    db_path = config.get("database", {}).get("path", "./results/vigia.db")
    conn = init_db(db_path)
    campaign_id = create_campaign(
        conn,
        name=f"scan_{target_model}_{int(time.time())}",
        target_model=target_model,
        config={**config, "mode": "scan", "fail_on_score": fail_on_score},
    )

    if not quiet:
        print(f"[vigia] Scanning {target_model} with {len(seeds)} seeds (threshold >= {fail_on_score})...", file=sys.stderr)

    delay = config.get("campaign", {}).get("delay_between_attacks", 1)

    for i, seed in enumerate(seeds):
        # Query target
        try:
            target_result = target.query(seed["prompt"])
            result.total_executed += 1
        except Exception as e:
            result.total_errors += 1
            record_attack(conn, campaign_id, {
                "seed_id": seed["id"],
                "vector": seed.get("vector", "unknown"),
                "owasp": seed.get("owasp"),
                "atlas": seed.get("atlas"),
                "language": seed.get("language"),
                "prompt": seed["prompt"],
                "response": f"[TARGET_ERROR] {e}",
                "chunks": [],
                "score": -1,
                "evaluator_reasoning": f"[ERROR] {e}",
                "duration_ms": 0,
            })
            continue

        # Evaluate
        try:
            evaluation = evaluate_with_llm(
                attack_prompt=seed["prompt"],
                target_response=target_result["response"],
                seed_info=seed,
                model=eval_model,
                provider=eval_provider,
                success_threshold=fail_on_score,
            )
        except Exception as e:
            result.total_errors += 1
            record_attack(conn, campaign_id, {
                "seed_id": seed["id"],
                "vector": seed.get("vector", "unknown"),
                "owasp": seed.get("owasp"),
                "atlas": seed.get("atlas"),
                "language": seed.get("language"),
                "prompt": seed["prompt"],
                "response": target_result["response"],
                "chunks": target_result.get("chunks", []),
                "score": -1,
                "evaluator_reasoning": f"[EVAL_ERROR] {e}",
                "duration_ms": target_result.get("duration_ms", 0),
            })
            continue

        finding = ScanFinding(
            seed_id=seed["id"],
            vector=seed.get("vector", "unknown"),
            owasp=seed.get("owasp", ""),
            score=evaluation.score,
            category=evaluation.category,
            reasoning=evaluation.reasoning,
            prompt=seed["prompt"],
            language=seed.get("language", "es-ES"),
            sensitive_data=evaluation.sensitive_data or [],
        )
        result.findings.append(finding)

        record_attack(conn, campaign_id, {
            "seed_id": seed["id"],
            "vector": seed.get("vector", "unknown"),
            "owasp": seed.get("owasp"),
            "atlas": seed.get("atlas"),
            "language": seed.get("language"),
            "prompt": seed["prompt"],
            "response": target_result["response"],
            "chunks": target_result.get("chunks", []),
            "score": evaluation.score,
            "evaluator_reasoning": f"[{evaluation.category}] {evaluation.reasoning}",
            "duration_ms": target_result.get("duration_ms", 0),
        })

        if delay and i < len(seeds) - 1:
            time.sleep(delay)

    finish_campaign(conn, campaign_id)
    conn.close()

    # Cleanup ChromaDB to release file locks
    if hasattr(target, 'vectorstore'):
        del target.vectorstore
    del target
    gc.collect()
    # Remove temp chroma dir
    try:
        shutil.rmtree(temp_chroma_dir, ignore_errors=True)
    except Exception:
        pass

    result.finished_at = datetime.now().isoformat()
    result.duration_ms = int((time.time() - start_time) * 1000)

    return result
