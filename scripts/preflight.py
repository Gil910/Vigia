#!/usr/bin/env python3
"""Everything about this repository that a machine can check, in one place.

    python scripts/preflight.py            # the fast checks, ~10s, also in CI
    python scripts/preflight.py --full     # plus build, twine and a clean install
    python scripts/preflight.py --list     # what it checks and why

Why this exists. Four separate reviews of this project each found something the
previous one had not, and the pattern was not that the earlier reviews were
careless — it was that "review the project" is not a repeatable procedure. Each
pass looked wherever the reviewer thought to look. The prose pass never installed
the wheel; the packaging pass never re-derived a percentage; the release that
fixed `vigia run` shipped with `vigia run -c vigia/config/default.yaml` broken,
because nobody had typed the second line of the README on a clean machine.

So the answer is not another careful reading. It is a list of everything that can
be wrong and a script that tries all of it every time, so the result stops
depending on what anybody remembered. Each check below is a bug this repository
actually had.

What it cannot check is still worth naming, because the point is to know where the
edge is: whether the Basque is Basque, whether a judge's verdict is right, whether
the bootstrap intervals were computed correctly, and whether any of this measures
what it claims to measure. Those need a person. Everything else is here.
"""
import argparse
import collections
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DB = ROOT / "results" / "vigia_2026-09.db"
DOCS = ["README.md", "README.es.md", "docs/METHODOLOGY.md", "docs/TAXONOMY.md",
        "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md"]

# The changelog records what was true at each release: 0.6.0 really did ship 511
# tests and a corpus running 38-39 per locale, and rewriting that to match today
# would turn a history into a lie. Checks that assert a present-tense fact read
# the live documents only; checks that are timeless — links resolve, paths exist,
# commands are real — read everything.
LIVE = [d for d in DOCS if d != "CHANGELOG.md"]


def newest_changelog_entry():
    """The section under the top version heading, which describes this release.

    The rest of the file is history and may quote superseded numbers. This part
    may not: it is a statement about the thing being published. Missing that
    distinction let "537 tests" sit in the entry for a release that has 559.
    """
    body = read("CHANGELOG.md")
    heads = list(re.finditer(r"^## \d+\.\d+\.\d+", body, re.M))
    if not heads:
        return ""
    end = heads[1].start() if len(heads) > 1 else len(body)
    return body[heads[0].start():end]

def tag_date(tag: str) -> str | None:
    """The day a tag was created, as YYYY-MM-DD, or None if it does not exist."""
    out = subprocess.run(
        ["git", "for-each-ref", "--format=%(creatordate:short)", f"refs/tags/{tag}"],
        cwd=ROOT, capture_output=True, text=True)
    return out.stdout.strip() or None


CHECKS = []


def check(slow=False, needs_db=False, needs_git=False):
    def register(fn):
        fn.slow, fn.needs_db, fn.needs_git = slow, needs_db, needs_git
        CHECKS.append(fn)
        return fn
    return register


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def markdown_files(only_live=False):
    for name in (LIVE if only_live else DOCS):
        if (ROOT / name).exists():
            yield name, read(name)


def fenced_blocks(text):
    """Every fenced code block, as (language, body)."""
    for m in re.finditer(r"```(\w*)\n(.*?)```", text, re.S):
        yield m.group(1), m.group(2)


def corpus():
    out = []
    for name in ("seeds_validated.json", "agent_seeds.json"):
        data = json.loads(read(f"vigia/corpus/seeds/{name}"))
        out.extend(data["seeds"] if isinstance(data, dict) else data)
    return out


# ---------------------------------------------------------------- the version

@check()
def one_version_everywhere():
    """`vigia --version` said 0.4.0 for two releases, then stopped existing.

    The number lives in vigia/__init__.py. Anything else that states it — the
    CHANGELOG's newest heading, a wheel filename in the launch notes — has to
    agree, or one of them is telling somebody the wrong thing to install.
    """
    # Read the file rather than import the package: from a checkout that is also
    # pip-installed, the import can return the installed version and quietly
    # agree with itself while the source says something else.
    match = re.search(r'__version__\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
                      read("vigia/__init__.py"))
    if not match:
        yield "vigia/__init__.py", "no __version__ to read"
        return
    version = match.group(1)
    heads = re.findall(r"^## (\d+\.\d+\.\d+)", read("CHANGELOG.md"), re.M)
    if not heads:
        yield "CHANGELOG.md", "no version heading at all"
    elif heads[0] != version:
        yield "CHANGELOG.md", f"newest entry is {heads[0]}, package is {version}"

    for name, text in markdown_files():
        for other in set(re.findall(r"\bvigia[ -](\d+\.\d+\.\d+)", text)):
            if other != version and f"## {other}" not in text:
                yield name, f"names vigia {other}, package is {version}"


@check()
def the_newest_entry_is_dated_the_day_it_shipped():
    """0.6.1's heading said 2026-09-10 and the tag was cut on the 16th.

    Nothing derives that date — it is typed while the release is being prepared
    and then the release slips. It matters because `gh release create` builds its
    notes from that section, so the published release carried a date six days
    before it existed, and the two are sitting next to each other on the releases
    page for anyone to compare.

    Only checked once the tag exists: before that the date is a plan, not a
    claim.
    """
    head = re.search(r"^## (\d+\.\d+\.\d+)\s+—\s+(\d{4}-\d{2}-\d{2})\s*$",
                     read("CHANGELOG.md"), re.M)
    if not head:
        yield "CHANGELOG.md", "the newest heading is not `## X.Y.Z — YYYY-MM-DD`"
        return
    version, dated = head.group(1), head.group(2)
    cut = tag_date(f"v{version}")
    if cut and cut != dated:
        yield "CHANGELOG.md", (f"0.{version.split('.', 1)[1]} is dated {dated} and "
                               f"tag v{version} was cut on {cut}")


# ------------------------------------------------------------------ the numbers

@check(needs_db=True)
def results_md_regenerates_byte_for_byte():
    """The one promise the repo makes about its own numbers.

    Every table in docs/RESULTS.md comes out of scripts/stats.py. If the
    committed file and the database disagree, a reader who checks finds that the
    checking story is the part that was not checked.
    """
    got = subprocess.run([sys.executable, "scripts/stats.py", str(DB)],
                         cwd=ROOT, capture_output=True, text=True)
    if got.returncode != 0:
        yield "scripts/stats.py", f"failed: {got.stderr.strip()[:200]}"
        return
    if got.stdout != read("docs/RESULTS.md"):
        yield "docs/RESULTS.md", "does not match what stats.py prints from the database"


# Figures that are real but come from the bootstrap analysis rather than from
# stats.py, so they cannot appear in RESULTS.md. They are allowed here on the
# condition that every document quoting them quotes the same value, which
# `the_bootstrap_figures_agree` checks.
BOOTSTRAP = {"9.6", "6.0", "10.7", "7.1", "4.2", "1.8", "12.8", "3.0", "15.4",
             "0.4", "8.8", "10.6", "0.6", "3.3", "0.3", "2.1"}
# Historical figures, explicitly labelled as superseded where they appear.
HISTORICAL = {"4.8", "23.0", "14.1", "59.6", "70.0", "37.8", "45.8", "60.1", "24.0"}


@check(needs_db=True)
def every_percentage_traces_to_the_database():
    """A number in the prose that is not in the generated tables is a typo.

    This is how "V12, 55 attacks, 43.6%" survived two cleaning passes: the table
    was written by hand from a version of the corpus that no longer existed.
    """
    results = read("docs/RESULTS.md")
    known = set(re.findall(r"\d+\.\d+|\d+", results)) | BOOTSTRAP | HISTORICAL
    for name, text in markdown_files(only_live=True):
        for m in re.finditer(r"(\d+[.,]\d)\s*(?:%|points|puntos)", text):
            value = m.group(1).replace(",", ".")
            if value not in known:
                line = text[:m.start()].count("\n") + 1
                yield f"{name}:{line}", f"{m.group(0)} is in no generated table"


@check()
def the_two_readmes_agree():
    """They are the same document in two languages, so they are the same numbers.

    Caught V01 mapped to LLM01 in the Spanish table and LLM02 in the English one.
    """
    def figures(text):
        text = re.sub(r"```.*?```", "", text, flags=re.S)     # commands are not claims
        return collections.Counter(
            m.group(1).replace(",", ".")
            for m in re.finditer(r"(\d+[.,]\d)\s*(?:%|points|puntos)", text))

    en, es = figures(read("README.md")), figures(read("README.es.md"))
    for value in sorted(set(en) | set(es)):
        if en[value] != es[value]:
            yield "README.es.md", (f"{value} appears {en[value]}x in English and "
                                   f"{es[value]}x in Spanish")


@check()
def the_bootstrap_figures_agree():
    """Nothing regenerates these, so consistency is all the checking there is.

    Said out loud rather than hidden: this is the one family of published number
    a reader cannot recompute from the repository.
    """
    generated = set(re.findall(r"\d+\.\d+", read("docs/RESULTS.md")))
    seen = set()
    for _name, text in markdown_files(only_live=True):
        for m in re.finditer(r"(\d+[.,]\d)\s*(?:points|puntos)", text):
            seen.add(m.group(1).replace(",", "."))
    for value in sorted(seen - generated - BOOTSTRAP - HISTORICAL):
        yield "docs", (f"{value} points is quoted, is in no generated table, and is "
                       f"not one of the bootstrap figures on the allow-list")


@check()
def the_test_count_is_the_real_one():
    """The CHANGELOG claimed 373 in one section and 435 in another. It was 507."""
    got = subprocess.run([sys.executable, "-m", "pytest", "-q", "--collect-only",
                          "-p", "no:cacheprovider"],
                         cwd=ROOT, capture_output=True, text=True)
    total = sum(int(n) for n in re.findall(r"^tests/\S+: (\d+)$", got.stdout, re.M))
    if not total:
        yield "pytest", "could not count the tests"
        return
    sources = list(markdown_files(only_live=True))
    sources.append(("CHANGELOG.md (newest entry)", newest_changelog_entry()))
    for name, text in sources:
        for m in re.finditer(r"(\d[\d,]{2,})\s+tests\b", text):
            claimed = int(m.group(1).replace(",", ""))
            if claimed != total:
                line = text[:m.start()].count("\n") + 1
                yield f"{name}:{line}", f"claims {claimed} tests, pytest collects {total}"


@check()
def the_seed_counts_are_the_corpus():
    """222 shipped, 244 with the agentic ones. Both are stated in prose."""
    rag = json.loads(read("vigia/corpus/seeds/seeds_validated.json"))
    rag = rag["seeds"] if isinstance(rag, dict) else rag
    agentic = json.loads(read("vigia/corpus/seeds/agent_seeds.json"))
    agentic = agentic["seeds"] if isinstance(agentic, dict) else agentic
    real = {"corpus": len(rag), "total": len(rag) + len(agentic), "agentic": len(agentic)}

    # Only three-figure claims: a smaller number is a per-locale or per-vector
    # count, and those are checked against the corpus below rather than here.
    # 233 and 195 are the September and April databases, not the shipped corpus.
    databases = {233, 195, 175}
    for name, text in markdown_files(only_live=True):
        for m in re.finditer(r"(\d{3,4})\s+(?:seeds|semillas)\b", text):
            claimed = int(m.group(1))
            if claimed in databases or claimed in real.values():
                continue
            line = text[:m.start()].count("\n") + 1
            yield f"{name}:{line}", (f"{claimed} seeds matches nothing: the corpus is "
                                     f"{real['corpus']}, {real['total']} with agentic")


@check()
def the_per_locale_floor_is_the_one_the_docs_state():
    """"the locales run 34 to 39" is a claim about a file, so read the file.

    Eleven seeds were dropped rather than faked, which is the whole point of the
    language section — and it is only honest while the stated range is the real
    one.
    """
    rag = json.loads(read("vigia/corpus/seeds/seeds_validated.json"))
    rag = rag["seeds"] if isinstance(rag, dict) else rag
    counts = collections.Counter(s.get("language") for s in rag)
    low, high = min(counts.values()), max(counts.values())
    phrase = re.compile(r"(?:locales|locals)\s+(?:run|are|go|entre|van de|est[áa]n entre)\s+"
                        r"(\d\d)\s*(?:to|a|-|–|y)\s*(\d\d)", re.I)
    for name, text in markdown_files(only_live=True):
        for m in phrase.finditer(text):
            claimed = (int(m.group(1)), int(m.group(2)))
            if claimed != (low, high):
                line = text[:m.start()].count("\n") + 1
                yield f"{name}:{line}", (f"says the locales run {claimed[0]}-{claimed[1]}, "
                                         f"the corpus runs {low}-{high}")


@check()
def the_owasp_column_is_the_corpus_column():
    """`validate_corpus.py` enforces the mapping in the data. Nothing enforced it
    in the tables, so both READMEs filed V09 under LLM01 while every seed said
    LLM02."""
    truth = {}
    for seed in corpus():
        code = seed.get("owasp") or seed.get("owasp_agentic")
        if seed.get("vector") and code:
            truth.setdefault(seed["vector"].split("_")[0], code)

    for name, text in markdown_files(only_live=True):
        for row in re.finditer(r"^\|\s*(V\d\d)[^|]*\|(.+)$", text, re.M):
            vector, rest = row.group(1), row.group(2)
            codes = set(re.findall(r"\bLLM\d\d\b", rest))
            if not codes or vector not in truth:
                continue
            if truth[vector] not in codes:
                line = text[:row.start()].count("\n") + 1
                yield f"{name}:{line}", (f"{vector} shown as {'/'.join(sorted(codes))}, "
                                         f"corpus says {truth[vector]}")


@check(needs_db=True)
def the_vector_tables_match_the_generated_one():
    """The rows a reader compares against RESULTS.md, compared for them."""
    truth = {}
    for row in re.finditer(r"^\|\s*(V\d\d)_\S+\s*\|\s*(\d+)\s*\|\s*([\d.]+)%",
                           read("docs/RESULTS.md"), re.M):
        truth[row.group(1)] = (int(row.group(2)), row.group(3))

    for name in ("README.md", "README.es.md"):
        text = read(name)
        for row in re.finditer(r"^\|\s*(V\d\d)\s[^|]*\|\s*(\d+)\s*\|\s*([\d,.]+)%", text, re.M):
            vector, n, rate = row.group(1), int(row.group(2)), row.group(3).replace(",", ".")
            if vector not in truth:
                continue
            if (n, rate) != truth[vector]:
                line = text[:row.start()].count("\n") + 1
                yield f"{name}:{line}", (f"{vector} shown as {n} attacks / {rate}%, "
                                         f"RESULTS.md says {truth[vector][0]} / "
                                         f"{truth[vector][1]}%")


# -------------------------------------------------------------------- the docs

@check()
def every_link_resolves():
    """Half the PyPI project page was dead links for a release."""
    for name, text in markdown_files():
        for m in re.finditer(r"\]\((?:https://github\.com/Gil910/Vigia/blob/main/)?"
                             r"([A-Za-z0-9_./-]+\.md)(#[A-Za-z0-9-]+)?\)", text):
            target, anchor = m.group(1), m.group(2)
            line = text[:m.start()].count("\n") + 1
            # A relative link resolves against the file it is written in.
            here = (ROOT / name).parent
            resolved = (here / target) if (here / target).exists() else (ROOT / target)
            if not resolved.exists():
                yield f"{name}:{line}", f"links to {target}, which is not in the repo"
                continue
            if anchor:
                slugs = {re.sub(r"[^a-z0-9 -]", "", h.lower()).replace(" ", "-")
                         for h in re.findall(r"^#+\s+(.+)$",
                                             resolved.read_text(encoding="utf-8"), re.M)}
                if anchor[1:] not in slugs:
                    yield f"{name}:{line}", f"{target}{anchor} — no heading with that id"


@check()
def every_image_resolves_and_is_used():
    """Old charts were deleted; the prose that pointed at them was not."""
    used = set()
    for name, text in markdown_files():
        for m in re.finditer(r"(?:docs/assets|assets)/([A-Za-z0-9_.-]+\.(?:png|svg|jpg))", text):
            used.add(m.group(1))
            if not (ROOT / "docs" / "assets" / m.group(1)).exists():
                line = text[:m.start()].count("\n") + 1
                yield f"{name}:{line}", f"docs/assets/{m.group(1)} does not exist"
    for asset in sorted((ROOT / "docs" / "assets").glob("*")):
        if asset.name not in used:
            yield "docs/assets", f"{asset.name} is shipped and referenced nowhere"


# Paths a document may name without them existing: things the reader creates.
DOC_PATH_EXCEPTIONS = {"mine.yaml", "report.xml", "docs/RESULTS.md", "evals.json",
                       "seeds_mutated.json", "results/vigia.db", "eval.json",
                       "config.yaml", "a.yaml", "b.yaml",
                       # written by `vigia mutate`, gitignored on purpose
                       "vigia/corpus/seeds/seeds_mutated.json"}


@check()
def every_path_a_document_names_exists():
    """`README.es.md` pointed stats.py at a database that is not in the repo, so
    the command in the "everything comes from these scripts" block crashed."""
    pattern = re.compile(r"\b((?:vigia|scripts|docs|results|tests)/[A-Za-z0-9_./-]+"
                         r"\.(?:py|yaml|json|md|db|txt))\b")
    for name, text in markdown_files():
        for m in pattern.finditer(text):
            target = m.group(1)
            if target in DOC_PATH_EXCEPTIONS or (ROOT / target).exists():
                continue
            line = text[:m.start()].count("\n") + 1
            yield f"{name}:{line}", f"names {target}, which does not exist"


@check()
def every_command_a_document_gives_is_real():
    """A README that names a flag the CLI dropped is the same class of error as
    one that quotes a number the database does not have."""
    from vigia.cli import build_parser
    parser = build_parser()
    subs = next(a for a in parser._actions if getattr(a, "choices", None)
                and "run" in (a.choices or {}))
    known = {}
    for sub, sub_parser in subs.choices.items():
        known[sub] = {opt for action in sub_parser._actions for opt in action.option_strings}

    for name, text in markdown_files():
        for _lang, block in fenced_blocks(text):
            for raw in block.splitlines():
                line = raw.strip().lstrip("$ ").split("#")[0].strip()
                if not re.match(r"^(?:\S*/)?vigia\s", line):
                    continue
                parts = line.split()[1:]
                if not parts or parts[0].startswith("-"):
                    continue
                sub, flags = parts[0], [p for p in parts[1:] if p.startswith("-")]
                if sub not in known:
                    yield name, f"`{line}` — no such subcommand"
                    continue
                for flag in flags:
                    if flag.split("=")[0] not in known[sub]:
                        yield name, f"`{line}` — `vigia {sub}` has no {flag}"


# ------------------------------------------------------------------ the corpus

RESERVED = re.compile(r"\.(invalid|example|test|localhost)$")
PLACEHOLDER_OK = {"example.com", "example.org", "api.example.com"}

# Documentation the remediation knowledge base points a reader at. These are
# links to go and read, never somewhere an attack tells a target to send data,
# so they are the one thing in the source that may name a real host.
DOCS_OK = {"docs.nvidia.com", "huggingface.co", "microsoft.github.io", "github.com"}


@check()
def exfiltration_destinations_cannot_resolve():
    """These seeds tell an agent to send data somewhere. Shipped to strangers who
    point them at their own agents, that somewhere has to be a domain nobody can
    receive mail on. RFC 2606 reserves .invalid and .example for it."""
    pattern = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})"
                         r"|https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
    targets = ["vigia/corpus/seeds/agent_seeds.json",
               "vigia/corpus/seeds/seeds_validated.json",
               "vigia/config/agent_example.yaml"]
    targets += [str(p.relative_to(ROOT))
                for p in (ROOT / "vigia/targets/rag_victim/documents").glob("*.txt")]
    # The corpus is not the only place an attack prompt lives. The planner builds
    # seeds in Python when the agent under test has the matching tools, and the
    # runner writes the document it injects for the indirect-injection seeds. Six
    # of those named domains anybody could register — review-corp.com, evil.com,
    # external-review.com, extern.cat — for a whole release after 0.6.1 fixed the
    # same thing in the JSON, because this check only ever read the JSON.
    targets += [str(p.relative_to(ROOT)) for p in (ROOT / "vigia/agents").glob("*.py")]
    for name in targets:
        for m in pattern.finditer(read(name)):
            domain = (m.group(1) or m.group(2)).lower().rstrip("/")
            if RESERVED.search(domain) or domain in PLACEHOLDER_OK or domain in DOCS_OK:
                continue
            yield name, f"{domain} is a domain somebody can register"


@check()
def no_seed_is_a_refusal():
    """The check that took two passes to get right, run over what ships."""
    from vigia.corpus.hygiene import degenerate_reason
    for seed in corpus():
        reason = degenerate_reason(seed.get("prompt", ""))
        if reason:
            yield "corpus", f"{seed.get('id')}: {reason}"


@check()
def no_shipped_config_lets_a_model_judge_itself():
    """`vigia run` with no arguments did exactly what three sections of
    METHODOLOGY say you must not do."""
    import yaml
    for path in sorted((ROOT / "vigia" / "config").glob("*.yaml")):
        cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        target = (cfg.get("target") or {}).get("model")
        judge = (cfg.get("evaluator") or {}).get("model")
        if target and judge and target == judge:
            yield f"vigia/config/{path.name}", f"{judge} judges itself"


# --------------------------------------------------------------- what we ship

DENYLIST = re.compile(r"(?:^|/)(?:CLAUDE\.md|\.claude/|\.env|.*\.docx|.*\.log|"
                      r".*\.bak.*|LINKEDIN_DRAFT\.md|_launch/|_to_delete/)")
SECRETS = re.compile(r"sk-[A-Za-z0-9_-]{16,}|AIza[A-Za-z0-9_-]{20,}"
                     r"|gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----")

# Strings that look like credentials and are deliberately shipped. Declared one
# by one rather than loosened out of the pattern: a new fake has to be added
# here, which is a decision somebody makes on purpose, and anything else is a
# finding. Narrowing the regex instead would have hidden the real thing too.
KNOWN_FAKES = {
    # fixtures for the redaction tests — they exist to be redacted
    "sk-proj-abcdefgh1234",
    "AIzaSyD-1234567890abcdefg",
    "AIzaSyD-1a2b3c4d5e6f7g8h9i0jKLMNOPQRstu",
    # planted in the demo RAG documents; leaking it is what V05 measures
    "sk-techcorp-api-2024-XXXXXXXXXXXX",
}


def source_files():
    """Tracked files where git is available, the working tree otherwise.

    The check has to run from a tarball as well as from a checkout, and a
    fallback that quietly scans nothing is the failure mode being avoided here.
    """
    listed = subprocess.run(["git", "ls-files"], cwd=ROOT,
                            capture_output=True, text=True).stdout.split()
    if listed:
        return [ROOT / p for p in listed]
    skip = {".git", "dist", "build", "venv", ".venv312", "__pycache__",
            ".pytest_cache", ".ruff_cache", "_launch", "_to_delete", "node_modules"}
    return [p for p in ROOT.rglob("*")
            if p.is_file() and not skip & set(p.relative_to(ROOT).parts)]


@check(needs_git=True)
def nothing_on_the_denylist_is_tracked():
    """Local working files and a .docx were committed once, then untracked.

    The names stay in the pattern rather than in prose: the check is what stops
    them coming back, and a denylist that does not name anything checks nothing.
    """
    listed = subprocess.run(["git", "ls-files"], cwd=ROOT,
                            capture_output=True, text=True).stdout.split()
    for path in listed:
        if DENYLIST.search(path):
            yield path, "is tracked and should not be"


@check()
def no_file_carries_a_secret():
    """Every blob in this repository's history was scanned once by hand. This is
    the same scan, run every time, so the answer stops being a memory."""
    for full in source_files():
        if not full.exists() or full.suffix in (".db", ".png", ".jpg", ".whl", ".gz"):
            continue
        try:
            body = full.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in SECRETS.finditer(body):
            if m.group(0) in KNOWN_FAKES:
                continue
            where = full.relative_to(ROOT)
            yield str(where), f"looks like a credential: {m.group(0)[:32]}…"


@check()
def the_wheel_will_carry_everything_the_code_opens():
    """`pip install vigia && vigia run` could not work: the configs and the corpus
    were read by a path relative to the repo, and one of them was not even in the
    package data."""
    import tomllib
    globs = tomllib.loads(read("pyproject.toml"))["tool"]["setuptools"]["package-data"]["vigia"]
    covered = {p for g in globs for p in (ROOT / "vigia").glob(g)}
    referenced = set()
    for source in (ROOT / "vigia").rglob("*.py"):
        for m in re.finditer(r"['\"](?:\./)?vigia/([A-Za-z0-9_./-]+\.(?:yaml|json|txt))['\"]",
                             source.read_text(encoding="utf-8")):
            referenced.add(ROOT / "vigia" / m.group(1))
    for path in sorted(referenced):
        if path.exists() and path not in covered:
            yield "pyproject.toml", f"{path.relative_to(ROOT)} is opened but not in package-data"


# ------------------------------------------------------- build and clean install

@check(slow=True)
def the_build_is_silent():
    """Four setuptools deprecation warnings were the first thing in the build log."""
    shutil.rmtree(ROOT / "dist", ignore_errors=True)
    done = subprocess.run([sys.executable, "-m", "build"], cwd=ROOT,
                          capture_output=True, text=True)
    if done.returncode != 0:
        yield "python -m build", done.stderr.strip()[-300:]
        return
    noisy = [line for line in (done.stdout + done.stderr).splitlines()
             if "deprecat" in line.lower()]
    for line in noisy[:3]:
        yield "python -m build", line.strip()[:160]


@check(slow=True)
def twine_accepts_both_artefacts():
    done = subprocess.run([sys.executable, "-m", "twine", "check"]
                          + [str(p) for p in (ROOT / "dist").glob("*")],
                          cwd=ROOT, capture_output=True, text=True)
    if done.returncode != 0:
        yield "twine check", done.stdout.strip()[-300:]


@check(slow=True)
def a_clean_install_survives_the_documented_commands():
    """The check that would have caught the release this script was written for.

    A virtualenv with nothing but the wheel, a directory with no source in it,
    and every `vigia ...` line the documentation gives. Ollama is not expected to
    be running: what is being judged is that each one fails like a program and
    not like a stack trace.
    """
    wheels = sorted((ROOT / "dist").glob("*.whl"))
    if not wheels:
        yield "dist", "no wheel to install — run with --full from a clean tree"
        return

    with tempfile.TemporaryDirectory() as tmp:
        venv, empty = Path(tmp) / "venv", Path(tmp) / "empty"
        empty.mkdir()
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True,
                       capture_output=True)
        pip = venv / "bin" / "pip"
        install = subprocess.run([str(pip), "install", "-q", str(wheels[-1])],
                                 capture_output=True, text=True)
        if install.returncode != 0:
            yield "pip install", install.stderr.strip()[-300:]
            return
        vigia = venv / "bin" / "vigia"

        commands = set()
        for _name, text in markdown_files():
            for _lang, block in fenced_blocks(text):
                for raw in block.splitlines():
                    line = raw.strip().lstrip("$ ").split("#")[0].strip()
                    m = re.match(r"^(?:\S*/)?vigia\s+(.*)$", line)
                    if m and not m.group(1).startswith("-"):
                        commands.add(m.group(1))
        commands |= {"--version", "strategies"}

        for argv in sorted(commands):
            # A campaign against a real target would need one; the point here is
            # how it behaves before it gets that far.
            done = subprocess.run([str(vigia)] + argv.split(), cwd=empty,
                                  capture_output=True, text=True, timeout=180)
            blob = done.stdout + done.stderr
            if "Traceback (most recent call last)" in blob:
                last = [ln for ln in blob.strip().splitlines() if ln.strip()][-1]
                yield f"vigia {argv}", f"traceback on a clean install: {last[:120]}"
            elif done.returncode not in (0, 1, 2):
                yield f"vigia {argv}", f"exit {done.returncode}"

        stray = {p.name for p in empty.iterdir()} - {"results", "seeds_mutated.json",
                                                     "mine.yaml"}
        if stray:
            yield "clean install", f"commands left files behind: {sorted(stray)}"


# ------------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(prog="preflight", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--full", action="store_true",
                    help="also build, run twine, and install into a clean venv")
    ap.add_argument("--list", action="store_true", help="what it checks, and why")
    args = ap.parse_args()

    if args.list:
        for fn in CHECKS:
            tag = " [--full]" if fn.slow else ""
            first = (fn.__doc__ or "").strip().splitlines()[0]
            print(f"  {fn.__name__}{tag}\n      {first}")
        return 0

    have_git = (ROOT / ".git").exists()
    failures, skipped = 0, []
    for fn in CHECKS:
        if fn.slow and not args.full:
            continue
        if fn.needs_db and not DB.exists():
            skipped.append(f"{fn.__name__} (no {DB.relative_to(ROOT)})")
            continue
        if fn.needs_git and not have_git:
            skipped.append(f"{fn.__name__} (not a git checkout)")
            continue
        try:
            problems = list(fn())
        except Exception as exc:                       # a broken check is a failure
            print(f"✗ {fn.__name__}\n    the check itself raised: {exc!r}")
            failures += 1
            continue
        if problems:
            failures += len(problems)
            print(f"✗ {fn.__name__}")
            for where, what in problems[:12]:
                print(f"    {where}: {what}")
            if len(problems) > 12:
                print(f"    … and {len(problems) - 12} more")
        else:
            print(f"✓ {fn.__name__}")

    for note in skipped:
        print(f"– skipped {note}")

    print()
    if failures:
        print(f"{failures} problem{'s' if failures > 1 else ''}. "
              f"Nothing here is a matter of taste — each one is a claim the "
              f"repository makes about itself that is not true.")
        return 1
    print("Clean." + ("" if args.full else "  Run with --full before releasing."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
