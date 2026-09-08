"""Tests para vigia.scanner — CI/CD gate mode."""

import json

import pytest

from vigia.scanner import ScanFinding, ScanResult, _xml_escape


class TestScanFinding:
    """Tests for individual scan findings."""

    def test_create_finding(self):
        f = ScanFinding(
            seed_id="ES-V01-001",
            vector="numerical_anchor",
            owasp="LLM02",
            score=7,
            category="pii_disclosure",
            reasoning="Salary data leaked",
            prompt="test prompt",
            language="es-ES",
            sensitive_data=["52000", "Juan Pérez"],
        )
        assert f.score == 7
        assert len(f.sensitive_data) == 2


class TestScanResult:
    """Tests for aggregated scan results."""

    @pytest.fixture
    def result_with_vulns(self):
        return ScanResult(
            target_model="llama3.1:8b",
            total_seeds=5,
            total_executed=5,
            total_errors=0,
            threshold=5,
            findings=[
                ScanFinding("S1", "v1", "LLM02", 8, "pii", "leaked", "p1", "es-ES", ["data1"]),
                ScanFinding("S2", "v2", "LLM02", 6, "pii", "partial", "p2", "es-ES"),
                ScanFinding("S3", "v3", "LLM07", 3, "info", "blocked", "p3", "es-ES"),
                ScanFinding("S4", "v4", "LLM02", 0, "safe", "no leak", "p4", "ca-ES"),
                ScanFinding("S5", "v5", "LLM02", 9, "pii", "full leak", "p5", "eu-ES", ["name", "salary"]),
            ],
        )

    @pytest.fixture
    def result_clean(self):
        return ScanResult(
            target_model="claude-3-haiku",
            total_seeds=3,
            total_executed=3,
            total_errors=0,
            threshold=5,
            findings=[
                ScanFinding("S1", "v1", "LLM02", 2, "info", "ok", "p1", "es-ES"),
                ScanFinding("S2", "v2", "LLM07", 0, "safe", "blocked", "p2", "es-ES"),
                ScanFinding("S3", "v3", "LLM02", 4, "info", "minor", "p3", "es-ES"),
            ],
        )

    @pytest.fixture
    def result_errors_only(self):
        return ScanResult(
            target_model="broken-model",
            total_seeds=2,
            total_executed=0,
            total_errors=2,
            threshold=5,
        )

    # --- Properties ---

    def test_vulnerabilities_filters_by_threshold(self, result_with_vulns):
        vulns = result_with_vulns.vulnerabilities
        assert len(vulns) == 3
        assert all(v.score >= 5 for v in vulns)

    def test_critical_filters_score_7_plus(self, result_with_vulns):
        crits = result_with_vulns.critical
        assert len(crits) == 2
        assert all(c.score >= 7 for c in crits)

    def test_passed_false_when_vulns(self, result_with_vulns):
        assert result_with_vulns.passed is False

    def test_passed_true_when_clean(self, result_clean):
        assert result_clean.passed is True

    def test_exit_code_1_when_vulns(self, result_with_vulns):
        assert result_with_vulns.exit_code == 1

    def test_exit_code_0_when_clean(self, result_clean):
        assert result_clean.exit_code == 0

    def test_exit_code_2_when_all_errors(self, result_errors_only):
        assert result_errors_only.exit_code == 2

    # --- Custom threshold ---

    def test_custom_threshold(self):
        result = ScanResult(
            target_model="test",
            total_seeds=2,
            total_executed=2,
            total_errors=0,
            threshold=8,
            findings=[
                ScanFinding("S1", "v1", "LLM02", 7, "pii", "high but below", "p1", "es-ES"),
                ScanFinding("S2", "v2", "LLM02", 5, "pii", "medium", "p2", "es-ES"),
            ],
        )
        assert result.passed is True
        assert result.exit_code == 0

    # --- Output formats ---

    def test_to_summary_contains_status(self, result_with_vulns, result_clean):
        assert "FAILED" in result_with_vulns.to_summary()
        assert "PASSED" in result_clean.to_summary()

    def test_to_summary_contains_model(self, result_with_vulns):
        assert "llama3.1:8b" in result_with_vulns.to_summary()

    def test_to_json_is_valid(self, result_with_vulns):
        parsed = json.loads(result_with_vulns.to_json())
        scan = parsed["vigia_scan"]
        assert scan["status"] == "failed"
        assert scan["total_vulnerabilities"] == 3
        assert scan["total_critical"] == 2
        assert len(scan["findings"]) == 5

    def test_to_json_clean_scan(self, result_clean):
        parsed = json.loads(result_clean.to_json())
        assert parsed["vigia_scan"]["status"] == "passed"
        assert parsed["vigia_scan"]["total_vulnerabilities"] == 0

    def test_to_junit_valid_xml_structure(self, result_with_vulns):
        xml = result_with_vulns.to_junit()
        assert '<?xml version="1.0"' in xml
        assert "<testsuites" in xml
        assert "<testsuite" in xml
        assert "<failure" in xml
        assert xml.count("<failure") == 3  # 3 vulns

    def test_to_junit_clean_no_failures(self, result_clean):
        xml = result_clean.to_junit()
        assert "<failure" not in xml
        assert 'failures="0"' in xml

    def test_to_junit_failure_contains_score(self, result_with_vulns):
        xml = result_with_vulns.to_junit()
        assert "Score 8/10" in xml
        assert "Score 9/10" in xml


class TestXmlEscape:
    """Tests for XML escaping utility."""

    def test_escapes_ampersand(self):
        assert _xml_escape("a & b") == "a &amp; b"

    def test_escapes_angle_brackets(self):
        assert _xml_escape("<tag>") == "&lt;tag&gt;"

    def test_escapes_quotes(self):
        assert _xml_escape('say "hello"') == "say &quot;hello&quot;"

    def test_no_escape_needed(self):
        assert _xml_escape("normal text") == "normal text"

    def test_spanish_characters_preserved(self):
        assert _xml_escape("¿Cuánto gana José?") == "¿Cuánto gana José?"


class TestCorpusSize:
    """El banner dice cuántas semillas hay. Tiene que ser verdad."""

    def test_it_counts_the_corpora_the_commands_fire(self, tmp_path):
        """Contar todos los json del directorio sumaba seeds_mutated.json.

        Ese fichero es la salida por defecto de `vigia mutate`, así que el
        banner anunciaba un corpus casi el doble del que ataca. Ya no se
        distribuye, y por eso el señuelo lo pone aquí el test: si dependiera de
        que hubiera un json de sobra en el directorio, dejaría de distinguir el
        fallo en cuanto alguien limpiase la carpeta.
        """
        import json
        from pathlib import Path

        from vigia.cli import CORPUS_FILES, _count_seeds

        seeds = Path(__file__).resolve().parent.parent / "vigia" / "corpus" / "seeds"
        expected = sum(len(json.loads((seeds / n).read_text(encoding="utf-8")))
                       for n in CORPUS_FILES)
        assert _count_seeds() == expected

        decoy = seeds / "seeds_mutated.json"
        assert not decoy.exists(), "el señuelo no puede existir ya"
        decoy.write_text(json.dumps([{"id": f"X-{i}"} for i in range(7)]),
                         encoding="utf-8")
        try:
            assert _count_seeds() == expected, (
                f"un json de más en el directorio subió la cuenta a "
                f"{_count_seeds()}; solo cuentan {CORPUS_FILES}")
        finally:
            decoy.unlink()

    def test_every_locale_carries_the_same_corpus(self):
        """El hallazgo lingüístico entero depende de esto.

        Durante meses el corpus tenía 1 semilla catalana contra 39 de cada otro
        idioma, y la comparación entre idiomas era en realidad una comparación
        entre vectores.
        """
        import collections
        import json
        from pathlib import Path

        seeds = json.loads((Path(__file__).resolve().parent.parent / "vigia" / "corpus"
                            / "seeds" / "seeds_validated.json").read_text())
        by_locale = collections.Counter(s["language"] for s in seeds)
        assert len(by_locale) == 6, by_locale
        assert max(by_locale.values()) - min(by_locale.values()) <= 1, by_locale
        vectors = {loc: {s["vector"] for s in seeds if s["language"] == loc}
                   for loc in by_locale}
        shared = set.intersection(*vectors.values())
        assert len(shared) == 19, f"solo {len(shared)} vectores en los seis locales"
