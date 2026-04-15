"""
VIGÍA — Benchmark (cross-model comparison)
Runs the same seed corpus against multiple model configs and generates
a comparative resistance table.

Usage:
    vigia benchmark -c config1.yaml config2.yaml config3.yaml
    vigia benchmark -c vigia/config/*.yaml --format markdown
"""

import json
import time
from dataclasses import dataclass, field
from typing import Optional

import yaml

from vigia.scanner import run_scan, ScanResult


@dataclass
class ModelScore:
    """Aggregated scores for a single model in the benchmark."""
    model: str
    config_path: str
    total_seeds: int = 0
    total_executed: int = 0
    total_errors: int = 0
    total_vulns: int = 0
    total_critical: int = 0
    avg_score: float = 0.0
    max_score: int = 0
    vuln_rate: float = 0.0
    vectors_breached: list[str] = field(default_factory=list)
    scan_result: Optional[ScanResult] = None


@dataclass
class BenchmarkResult:
    """Aggregated benchmark across all models."""
    corpus_path: str
    threshold: int
    models: list[ModelScore] = field(default_factory=list)
    duration_ms: int = 0

    @property
    def most_resistant(self) -> Optional[ModelScore]:
        """Model with lowest vulnerability rate."""
        executed = [m for m in self.models if m.total_executed > 0]
        return min(executed, key=lambda m: m.vuln_rate) if executed else None

    @property
    def least_resistant(self) -> Optional[ModelScore]:
        """Model with highest vulnerability rate."""
        executed = [m for m in self.models if m.total_executed > 0]
        return max(executed, key=lambda m: m.vuln_rate) if executed else None

    def to_table(self) -> str:
        """ASCII table for terminal output."""
        if not self.models:
            return "[vigia benchmark] No models tested."

        # Header
        lines = [
            "",
            f"  VIGÍA Benchmark — {len(self.models)} models × {self.models[0].total_seeds} seeds (threshold >= {self.threshold})",
            "  " + "=" * 90,
            f"  {'Model':<35} {'Vuln Rate':>10} {'Vulns':>6} {'Crit':>6} {'Avg':>6} {'Max':>5} {'Errors':>7}",
            "  " + "-" * 90,
        ]

        # Sort by vuln_rate ascending (most resistant first)
        # Exclude models with 0 executed (all errors — likely missing API keys)
        valid_models = [m for m in self.models if m.total_executed > 0]
        error_models = [m for m in self.models if m.total_executed == 0 and m.total_errors > 0]
        sorted_models = sorted(valid_models, key=lambda m: m.vuln_rate)

        for m in sorted_models:
            bar = _resistance_bar(m.vuln_rate)
            lines.append(
                f"  {m.model:<35} {m.vuln_rate:>9.1f}% {m.total_vulns:>6} {m.total_critical:>6} "
                f"{m.avg_score:>5.1f} {m.max_score:>5} {m.total_errors:>7}  {bar}"
            )

        if error_models:
            lines.append("  " + "-" * 90)
            for m in error_models:
                lines.append(
                    f"  {m.model:<35} {'N/A':>10} {'—':>6} {'—':>6} "
                    f"{'—':>6} {'—':>5} {m.total_errors:>7}  ⚠ errors only"
                )

        lines.append("  " + "=" * 90)

        best = self.most_resistant
        worst = self.least_resistant
        if best and worst and best.model != worst.model:
            lines.append(f"  Most resistant:  {best.model} ({best.vuln_rate:.1f}% vuln rate)")
            lines.append(f"  Least resistant: {worst.model} ({worst.vuln_rate:.1f}% vuln rate)")

        lines.append(f"  Duration: {self.duration_ms / 1000:.1f}s")
        lines.append("")
        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Markdown table for README / reports."""
        if not self.models:
            return "No models tested."

        valid_models = [m for m in self.models if m.total_executed > 0]
        sorted_models = sorted(valid_models, key=lambda m: m.vuln_rate)

        lines = [
            f"## VIGÍA Benchmark — {len(sorted_models)} models (threshold >= {self.threshold})",
            "",
            "| Model | Vuln Rate | Vulns | Critical | Avg Score | Max Score | Errors |",
            "|-------|-----------|-------|----------|-----------|-----------|--------|",
        ]

        for m in sorted_models:
            lines.append(
                f"| {m.model} | {m.vuln_rate:.1f}% | {m.total_vulns}/{m.total_executed} | "
                f"{m.total_critical} | {m.avg_score:.1f} | {m.max_score} | {m.total_errors} |"
            )

        lines.append("")

        best = self.most_resistant
        worst = self.least_resistant
        if best and worst:
            lines.append(f"**Most resistant:** {best.model} ({best.vuln_rate:.1f}% vuln rate)  ")
            lines.append(f"**Least resistant:** {worst.model} ({worst.vuln_rate:.1f}% vuln rate)")

        return "\n".join(lines)

    def to_json(self) -> str:
        """JSON output for programmatic consumption."""
        return json.dumps({
            "vigia_benchmark": {
                "corpus": self.corpus_path,
                "threshold": self.threshold,
                "duration_ms": self.duration_ms,
                "models": [
                    {
                        "model": m.model,
                        "config": m.config_path,
                        "total_seeds": m.total_seeds,
                        "total_executed": m.total_executed,
                        "total_errors": m.total_errors,
                        "total_vulns": m.total_vulns,
                        "total_critical": m.total_critical,
                        "avg_score": round(m.avg_score, 2),
                        "max_score": m.max_score,
                        "vuln_rate": round(m.vuln_rate, 2),
                        "vectors_breached": m.vectors_breached,
                    }
                    for m in sorted(self.models, key=lambda m: m.vuln_rate)
                ],
                "most_resistant": self.most_resistant.model if self.most_resistant else None,
                "least_resistant": self.least_resistant.model if self.least_resistant else None,
            }
        }, indent=2, ensure_ascii=False)


def _resistance_bar(vuln_rate: float, width: int = 20) -> str:
    """Visual resistance bar: ████████░░░░ (more filled = more vulnerable)."""
    filled = int(vuln_rate / 100 * width)
    filled = min(filled, width)
    empty = width - filled
    if vuln_rate == 0:
        return "░" * width + " ✓"
    elif vuln_rate >= 50:
        return "█" * filled + "░" * empty + " ✗"
    else:
        return "█" * filled + "░" * empty


def run_benchmark(
    config_paths: list[str],
    corpus_path: str,
    threshold: int = 5,
    quiet: bool = False,
) -> BenchmarkResult:
    """
    Run the same corpus against multiple model configs.
    Returns aggregated comparison results.
    """
    import sys

    start = time.time()
    result = BenchmarkResult(
        corpus_path=corpus_path,
        threshold=threshold,
    )

    # Filter out configs that don't have a 'target' key (e.g. agent configs)
    # or are example/unreachable targets (http_example)
    valid_configs = []
    skip_patterns = ("example", "schemas")
    for cp in config_paths:
        if any(p in cp for p in skip_patterns):
            if not quiet:
                print(f"[vigia] SKIP {cp}: example/schema config", file=sys.stderr)
            continue
        try:
            with open(cp, "r") as f:
                c = yaml.safe_load(f)
            if "target" not in c:
                if not quiet:
                    print(f"[vigia] SKIP {cp}: no 'target' key (agent config?)", file=sys.stderr)
                continue
            valid_configs.append(cp)
        except Exception as e:
            if not quiet:
                print(f"[vigia] SKIP {cp}: {e}", file=sys.stderr)

    for i, config_path in enumerate(valid_configs):
        if not quiet:
            print(
                f"[vigia] Benchmark {i+1}/{len(valid_configs)}: {config_path}...",
                file=sys.stderr,
            )

        try:
            scan = run_scan(
                config_path=config_path,
                corpus_path=corpus_path,
                fail_on_score=threshold,
                quiet=True,
            )
        except Exception as e:
            if not quiet:
                print(f"[vigia] ERROR on {config_path}: {e}", file=sys.stderr)
            result.models.append(ModelScore(
                model=f"ERROR: {config_path}",
                config_path=config_path,
                total_errors=1,
            ))
            continue

        # Compute aggregated scores
        scores = [f.score for f in scan.findings]
        avg = sum(scores) / len(scores) if scores else 0.0
        max_s = max(scores) if scores else 0
        vectors = list(set(f.vector for f in scan.vulnerabilities))

        executed = max(scan.total_executed, 1)

        model_score = ModelScore(
            model=scan.target_model,
            config_path=config_path,
            total_seeds=scan.total_seeds,
            total_executed=scan.total_executed,
            total_errors=scan.total_errors,
            total_vulns=len(scan.vulnerabilities),
            total_critical=len(scan.critical),
            avg_score=avg,
            max_score=max_s,
            vuln_rate=len(scan.vulnerabilities) / executed * 100,
            vectors_breached=vectors,
            scan_result=scan,
        )
        result.models.append(model_score)

    result.duration_ms = int((time.time() - start) * 1000)
    return result
