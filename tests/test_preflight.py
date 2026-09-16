"""The checker gets checked.

`scripts/preflight.py` exists because four reviews in a row each found something
the last one missed. That argument only holds if the checks actually fire, so each
one here is handed a copy of the repository with exactly the defect it claims to
catch, and has to catch it. A check that cannot fail is worse than no check: it
reads like coverage and is decoration.

The repository is copied once per session and each test edits its own copy of the
file it needs, so nothing here can touch the real tree.
"""
import importlib.util
import shutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SKIP = {".git", ".venv312", "venv", "dist", "dist_new", "build", "__pycache__",
        ".pytest_cache", ".ruff_cache", "_launch", "_to_delete", "node_modules"}


def _load(root: Path):
    """Load preflight with its ROOT pointed at a copy of the repo."""
    spec = importlib.util.spec_from_file_location(
        f"preflight_{abs(hash(str(root)))}", REPO / "scripts" / "preflight.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    module.DB = root / "results" / "vigia_2026-09.db"
    return module


@pytest.fixture(scope="session")
def repo_copy(tmp_path_factory):
    dest = tmp_path_factory.mktemp("repo")
    shutil.copytree(REPO, dest / "vigia-repo",
                    ignore=shutil.ignore_patterns(*SKIP), symlinks=True)
    return dest / "vigia-repo"


@pytest.fixture
def sandbox(repo_copy, tmp_path):
    """A fresh copy per test, so one mutation cannot leak into another."""
    root = tmp_path / "repo"
    shutil.copytree(repo_copy, root, symlinks=True)
    return root


def edit(root: Path, relative: str, old: str, new: str):
    path = root / relative
    text = path.read_text(encoding="utf-8")
    assert text.count(old) >= 1, f"{relative}: nothing to replace ({old[:40]!r})"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def run(root: Path, name: str):
    module = _load(root)
    fn = next(f for f in module.CHECKS if f.__name__ == name)
    return list(fn())


def test_the_real_repository_is_clean(sandbox):
    """Every fast check, over an unmutated copy. If this fails the rest is noise."""
    module = _load(sandbox)
    problems = {}
    for fn in module.CHECKS:
        if fn.slow or (fn.needs_git and not (sandbox / ".git").exists()):
            continue
        found = list(fn())
        if found:
            problems[fn.__name__] = found
    assert not problems, problems


class TestEachCheckCatchesItsOwnDefect:
    """One mutation per check, each one a bug this repository actually shipped."""

    def test_a_version_that_disagrees_with_the_changelog(self, sandbox):
        edit(sandbox, "vigia/__init__.py", '__version__ = "', '__version__ = "9.9.9"  # "')
        assert run(sandbox, "one_version_everywhere")

    def test_a_results_table_edited_by_hand(self, sandbox):
        edit(sandbox, "docs/RESULTS.md", "| 70.9%", "| 70.8%")
        assert run(sandbox, "results_md_regenerates_byte_for_byte")

    def test_a_percentage_that_is_in_no_generated_table(self, sandbox):
        edit(sandbox, "README.md", "at **70.9%**", "at **77.3%**")
        assert run(sandbox, "every_percentage_traces_to_the_database")

    def test_a_figure_changed_in_one_language_only(self, sandbox):
        edit(sandbox, "README.es.md", "un **70,9%**", "un **70,4%**")
        assert run(sandbox, "the_two_readmes_agree")

    def test_a_points_figure_from_nowhere(self, sandbox):
        edit(sandbox, "docs/METHODOLOGY.md", "## What counts as a leak",
             "The gap is 8.3 points.\n\n## What counts as a leak")
        assert run(sandbox, "the_bootstrap_figures_agree")

    def test_a_stale_test_count(self, sandbox):
        edit(sandbox, "README.md", "## Install", "There are 999 tests.\n\n## Install")
        assert run(sandbox, "the_test_count_is_the_real_one")

    def test_a_seed_total_that_is_not_the_corpus(self, sandbox):
        edit(sandbox, "README.md", "The corpus ships 222 seeds",
             "The corpus ships 999 seeds")
        assert run(sandbox, "the_seed_counts_are_the_corpus")

    def test_a_locale_range_that_no_longer_holds(self, sandbox):
        edit(sandbox, "docs/METHODOLOGY.md",
             "the locales run 34 to 39", "the locales run 38 to 39")
        assert run(sandbox, "the_per_locale_floor_is_the_one_the_docs_state")

    def test_a_vector_filed_under_the_wrong_owasp_code(self, sandbox):
        edit(sandbox, "README.md", "| V05 passive context leak | 55 | 70.9% | LLM09 |",
             "| V05 passive context leak | 55 | 70.9% | LLM01 |")
        assert run(sandbox, "the_owasp_column_is_the_corpus_column")

    def test_a_vector_row_that_drifted_from_the_generated_table(self, sandbox):
        edit(sandbox, "README.md", "| V05 passive context leak | 55 |",
             "| V05 passive context leak | 80 |")
        assert run(sandbox, "the_vector_tables_match_the_generated_one")

    def test_a_link_to_a_file_that_was_deleted(self, sandbox):
        edit(sandbox, "README.md", "blob/main/docs/RESULTS.md",
             "blob/main/docs/RESULTADOS.md")
        assert run(sandbox, "every_link_resolves")

    def test_an_anchor_that_does_not_exist(self, sandbox):
        edit(sandbox, "README.md", "TAXONOMY.md#mitre-atlas", "TAXONOMY.md#mitre-atlaz")
        assert run(sandbox, "every_link_resolves")

    def test_an_image_that_was_deleted(self, sandbox):
        (sandbox / "docs" / "assets" / "reasoning-leak.png").unlink()
        assert run(sandbox, "every_image_resolves_and_is_used")

    def test_a_chart_nobody_references(self, sandbox):
        (sandbox / "docs" / "assets" / "language-leak-rate.png").write_bytes(b"x")
        assert run(sandbox, "every_image_resolves_and_is_used")

    def test_a_script_named_in_the_docs_that_is_not_there(self, sandbox):
        edit(sandbox, "README.md", "scripts/validate_corpus.py", "scripts/validar_corpus.py")
        assert run(sandbox, "every_path_a_document_names_exists")

    def test_a_subcommand_the_cli_does_not_have(self, sandbox):
        edit(sandbox, "README.md", "vigia strategies  ", "vigia frobnicate  ")
        assert run(sandbox, "every_command_a_document_gives_is_real")

    def test_a_flag_the_cli_does_not_have(self, sandbox):
        edit(sandbox, "README.md", "vigia scan --fail-on-score 5",
             "vigia scan --fail-on-scores 5")
        assert run(sandbox, "every_command_a_document_gives_is_real")

    def test_an_exfiltration_destination_somebody_could_register(self, sandbox):
        edit(sandbox, "vigia/corpus/seeds/agent_seeds.json",
             "evil.invalid", "evil.com")
        assert run(sandbox, "exfiltration_destinations_cannot_resolve")

    def test_a_refusal_written_into_the_corpus(self, sandbox):
        import json
        path = sandbox / "vigia" / "corpus" / "seeds" / "seeds_validated.json"
        seeds = json.loads(path.read_text(encoding="utf-8"))
        rows = seeds["seeds"] if isinstance(seeds, dict) else seeds
        rows[0]["prompt"] = "Lo siento, pero no puedo cumplir con esa solicitud."
        path.write_text(json.dumps(seeds, ensure_ascii=False, indent=2), encoding="utf-8")
        assert run(sandbox, "no_seed_is_a_refusal")

    def test_a_config_where_the_target_grades_itself(self, sandbox):
        edit(sandbox, "vigia/config/default.yaml", 'model: "mistral"',
             'model: "llama3.1:8b"')
        assert run(sandbox, "no_shipped_config_lets_a_model_judge_itself")

    def test_a_changelog_dated_before_the_tag_was_cut(self, sandbox):
        module = _load(sandbox)
        module.tag_date = lambda tag: "2026-09-20"
        fn = next(f for f in module.CHECKS
                  if f.__name__ == "the_newest_entry_is_dated_the_day_it_shipped")
        assert list(fn())

    def test_the_date_it_really_shipped_on_is_not_a_finding(self, sandbox):
        # The other direction: the heading and the tag agreeing has to be quiet,
        # or this gets muted the first time somebody cuts a tag.
        import re
        module = _load(sandbox)
        head = re.search(r"^## \d+\.\d+\.\d+\s+—\s+(\d{4}-\d{2}-\d{2})",
                         (sandbox / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
        module.tag_date = lambda tag: head.group(1)
        fn = next(f for f in module.CHECKS
                  if f.__name__ == "the_newest_entry_is_dated_the_day_it_shipped")
        assert not list(fn())

    def test_a_release_with_no_tag_yet_is_not_a_finding(self, sandbox):
        module = _load(sandbox)
        module.tag_date = lambda tag: None
        fn = next(f for f in module.CHECKS
                  if f.__name__ == "the_newest_entry_is_dated_the_day_it_shipped")
        assert not list(fn()), "before the tag exists the date is a plan, not a claim"

    def test_a_credential_that_is_not_a_declared_fixture(self, sandbox):
        # Assembled at runtime. Written out whole, this file would be the first
        # thing the check finds, which is a lesson about scanners scanning
        # themselves that cost one test run to learn.
        secret = "sk-" + "live-" + "Zq7RmT4xW9pL2vB8nK6hJ3dF"
        (sandbox / "vigia" / "leak.py").write_text(
            f'TOKEN = "{secret}"\n', encoding="utf-8")
        assert run(sandbox, "no_file_carries_a_secret")

    def test_the_fixtures_the_redaction_tests_need_are_not_a_finding(self, sandbox):
        # The other direction: a check that flags the repo's own deliberate fakes
        # gets muted within a week, and then it is not checking anything.
        assert not run(sandbox, "no_file_carries_a_secret")

    def test_package_data_that_stops_covering_the_configs(self, sandbox):
        edit(sandbox, "pyproject.toml", '"config/*.yaml",', "")
        assert run(sandbox, "the_wheel_will_carry_everything_the_code_opens")
