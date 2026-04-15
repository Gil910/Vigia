"""Tests para vigia.benchmark — cross-model comparison."""

import json
import pytest
from vigia.benchmark import BenchmarkResult, ModelScore, _resistance_bar


class TestModelScore:
    """Tests for individual model scores."""

    def test_create_model_score(self):
        m = ModelScore(
            model="llama3.1:8b",
            config_path="config/default.yaml",
            total_seeds=11,
            total_executed=11,
            total_errors=0,
            total_vulns=5,
            total_critical=2,
            avg_score=4.3,
            max_score=9,
            vuln_rate=45.5,
            vectors_breached=["numerical_anchor", "summary_exfil"],
        )
        assert m.model == "llama3.1:8b"
        assert m.vuln_rate == 45.5
        assert len(m.vectors_breached) == 2


class TestBenchmarkResult:
    """Tests for aggregated benchmark results."""

    @pytest.fixture
    def benchmark_3_models(self):
        return BenchmarkResult(
            corpus_path="seeds_validated.json",
            threshold=5,
            duration_ms=15000,
            models=[
                ModelScore("llama3.1:8b", "c1.yaml", 11, 11, 0, 6, 3, 5.2, 9, 54.5, ["v1", "v2"]),
                ModelScore("claude-haiku", "c2.yaml", 11, 11, 0, 2, 0, 2.8, 6, 18.2, ["v1"]),
                ModelScore("gemini-flash", "c3.yaml", 11, 11, 0, 4, 1, 3.9, 8, 36.4, ["v1", "v3"]),
            ],
        )

    @pytest.fixture
    def benchmark_clean(self):
        return BenchmarkResult(
            corpus_path="seeds.json",
            threshold=5,
            models=[
                ModelScore("secure-model", "c1.yaml", 5, 5, 0, 0, 0, 1.2, 3, 0.0),
            ],
        )

    @pytest.fixture
    def benchmark_empty(self):
        return BenchmarkResult(corpus_path="seeds.json", threshold=5)

    # --- Properties ---

    def test_most_resistant(self, benchmark_3_models):
        assert benchmark_3_models.most_resistant.model == "claude-haiku"

    def test_least_resistant(self, benchmark_3_models):
        assert benchmark_3_models.least_resistant.model == "llama3.1:8b"

    def test_most_resistant_none_when_empty(self, benchmark_empty):
        assert benchmark_empty.most_resistant is None

    # --- Table output ---

    def test_to_table_contains_all_models(self, benchmark_3_models):
        table = benchmark_3_models.to_table()
        assert "llama3.1:8b" in table
        assert "claude-haiku" in table
        assert "gemini-flash" in table

    def test_to_table_contains_header(self, benchmark_3_models):
        table = benchmark_3_models.to_table()
        assert "Benchmark" in table
        assert "3 models" in table

    def test_to_table_contains_resistance_info(self, benchmark_3_models):
        table = benchmark_3_models.to_table()
        assert "Most resistant" in table
        assert "claude-haiku" in table

    def test_to_table_empty(self, benchmark_empty):
        assert "No models" in benchmark_empty.to_table()

    # --- Markdown output ---

    def test_to_markdown_is_valid_table(self, benchmark_3_models):
        md = benchmark_3_models.to_markdown()
        assert "| Model |" in md
        assert "|-------|" in md
        assert "llama3.1:8b" in md

    def test_to_markdown_sorted_by_vuln_rate(self, benchmark_3_models):
        md = benchmark_3_models.to_markdown()
        lines = [l for l in md.split("\n") if l.startswith("| ") and "Model" not in l and "---" not in l]
        # claude-haiku (18.2%) should come before llama (54.5%)
        assert lines[0].startswith("| claude-haiku")
        assert lines[-1].startswith("| llama3.1:8b")

    # --- JSON output ---

    def test_to_json_valid(self, benchmark_3_models):
        parsed = json.loads(benchmark_3_models.to_json())
        bench = parsed["vigia_benchmark"]
        assert len(bench["models"]) == 3
        assert bench["threshold"] == 5
        assert bench["most_resistant"] == "claude-haiku"
        assert bench["least_resistant"] == "llama3.1:8b"

    def test_to_json_models_sorted(self, benchmark_3_models):
        parsed = json.loads(benchmark_3_models.to_json())
        models = parsed["vigia_benchmark"]["models"]
        rates = [m["vuln_rate"] for m in models]
        assert rates == sorted(rates)

    def test_to_json_clean(self, benchmark_clean):
        parsed = json.loads(benchmark_clean.to_json())
        bench = parsed["vigia_benchmark"]
        assert bench["models"][0]["total_vulns"] == 0
        assert bench["models"][0]["vuln_rate"] == 0.0


class TestResistanceBar:
    """Tests for visual resistance bar."""

    def test_zero_vuln_rate(self):
        bar = _resistance_bar(0)
        assert "✓" in bar
        assert "█" not in bar

    def test_high_vuln_rate(self):
        bar = _resistance_bar(80)
        assert "✗" in bar
        assert "█" in bar

    def test_mid_vuln_rate(self):
        bar = _resistance_bar(30)
        assert "█" in bar
        assert "░" in bar

    def test_hundred_percent(self):
        bar = _resistance_bar(100)
        assert "✗" in bar

    def test_custom_width(self):
        bar = _resistance_bar(50, width=10)
        assert len(bar.rstrip(" ✗✓")) <= 10
