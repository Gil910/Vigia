# Vigia

[![ci](https://github.com/Gil910/Vigia/actions/workflows/ci.yml/badge.svg)](https://github.com/Gil910/Vigia/actions/workflows/ci.yml)
[![pypi](https://img.shields.io/pypi/v/vigia)](https://pypi.org/project/vigia/)
![python](https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Red teaming for LLM applications, built around the languages spoken in Spain.

Almost all published LLM safety work is in English. Meanwhile Spanish banks,
hospitals and public administrations are shipping RAG chatbots in Spanish, and
sometimes in Catalan, Basque or Galician, on top of models whose safety training
was overwhelmingly English. Vigia is an attempt to measure how much that gap is
worth to an attacker.

Español: **[README.es.md](https://github.com/Gil910/Vigia/blob/main/README.es.md)**

---

## The short version

I ran 2,769 evaluated attacks against five models in six Iberian locales. Three
things came out of it.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/language-leak-rate-dark.png">
    <img src="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/language-leak-rate.png" alt="Leak rate by locale: Catalan 70.0%, Spanish 45.8%, Spanish+Basque 28.0%, Spanish+Galician 24.2%, Basque 24.1%, Galician 23.8%" width="820">
  </picture>
</p>

**Catalan is the soft spot.** 70.0% of attacks written in Catalan got a leak,
against 45.8% for the same attacks in Spanish. My reading is that Catalan sits in
an awkward middle: the models understand it well enough to follow a complex,
manipulative request, but not well enough for the safety training to fire. The
caveat is real though — this rests on 80 attacks, the smallest sample of the six
locales, and it is the number most likely to move.

**Basque and Galician came out safer, and I don't fully believe it.** eu-ES at
24.1% and gl-ES at 23.8%, well below Spanish. The obvious story is that
lower-resource languages are harder for the model to parse, so the attack lands
as noise rather than as an attack. But the judge is also worse at those languages,
so a leak it can't read scores zero. Marx and Dunaiski found something adjacent in
[May 2026](https://arxiv.org/abs/2605.18239): single-turn translated attacks fail
in low-resource languages while multi-turn ones succeed, and translation quality
is what decides it. My numbers are single-turn. That is the experiment to run next,
not a conclusion to publish.

**The retriever leaks more than the model does.** The highest-scoring vector in
the whole corpus is `V05_passive_context_leak` at 64.4%: ask something ordinary,
the retriever pulls a chunk that happens to contain a salary or an SSH key next to
the relevant text, and the model reads out what it was handed. No jailbreak, no
injection. Under the [OWASP 2026 list](https://genai.owasp.org/llm-top-10/) that
is LLM09 Vector and Embedding Weaknesses, and it is a retrieval design problem
that no amount of system-prompt hardening fixes.

Full tables: **[docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md)**. How the numbers are made and
where they break: **[docs/METHODOLOGY.md](https://github.com/Gil910/Vigia/blob/main/docs/METHODOLOGY.md)**.

## Why not just use garak or PyRIT

You probably should, alongside this. They cover far more ground. Vigia exists
because of three things they leave on the table, which the 2026 tool round-ups
tend to list as the open gaps in the category:

- Attacks written *in* Spanish, Catalan, Basque and Galician, rather than English
  probes machine-translated at run time. Translation quality changes the result,
  which is exactly the finding above.
- RAG-specific vectors that attack the retrieval step, not the model. Chunk
  adjacency, summary exfiltration, indirect injection through an indexed document.
- Agentic seeds mapped to the OWASP Agentic Top 10 as published in 2026, not to a
  pre-publication draft.

It is a small tool with a narrow thesis. If you need broad coverage, layer it.

## Install

```bash
pip install vigia
```

You need [Ollama](https://ollama.com) for the local models:

```bash
ollama serve                    # in another terminal
ollama pull llama3.1:8b
ollama pull nomic-embed-text    # embeddings for the demo RAG target
```

Then:

```bash
vigia run
```

That fires the corpus at a demo RAG chatbot bundled with the tool. The chatbot is
deliberately vulnerable and its documents are fictional: TechCorp España does not
exist and neither do its salaries. Nothing leaves your machine unless you point it
at something remote.

For commercial models as target or judge:

```bash
export ANTHROPIC_API_KEY=...
vigia run -c vigia/config/claude_haiku.yaml
```

## Pointing it at your own chatbot

```bash
cp vigia/config/http_example.yaml mine.yaml
```

```yaml
target:
  type: http
  url: https://api.example.com/chatbot/v1/message
  headers:
    Authorization: Bearer ${CHATBOT_TOKEN}
  request_format: simple
  request_field: message
  response_field: data.answer
```

```bash
vigia run -c mine.yaml
```

Only do this against something you own or have written permission to test. See
[SECURITY.md](https://github.com/Gil910/Vigia/blob/main/SECURITY.md).

## Commands

```bash
vigia run                                    # single-shot campaign
vigia multiturn --strategy escalation -n 10  # conversational, up to 8 turns
vigia multiturn --adaptive -n 10             # picks a strategy from past results
vigia agent                                  # attack an agent that has tools
vigia agent --plan                           # generate an attack plan first
vigia mutate -s euskera,gallego -m 5         # generate linguistic variants
vigia benchmark -c a.yaml b.yaml             # compare two targets
vigia scan --fail-on-score 5                 # CI gate, exits 1 on findings
vigia scan --format junit -o report.xml
vigia strategies                             # what's available
```

### Using it as a CI gate

`vigia scan` exits non-zero when it finds something above the threshold, and can
emit JUnit XML. One caveat, from the variance measurements: **gate on the
aggregate rate, never on a single seed**. Running the same 195 seeds twice flips
12–14% of individual verdicts while the overall rate stays within a point. A
per-seed gate will be flaky and your team will start ignoring it.

## What it attacks

**19 RAG vectors**, 195 seeds across six locales. The ones that actually work:

| Vector | Attacks | Leak rate | OWASP 2026 |
|--------|--------:|----------:|------------|
| V05 passive context leak | 188 | 64.4% | LLM09 |
| V01 numerical anchor | 349 | 63.6% | LLM02 |
| V09 compliant reformulation | 172 | 50.6% | LLM02 |
| V02 summary exfiltration | 214 | 46.7% | LLM02 |
| V08 chain-of-thought exploit | 136 | 41.2% | LLM02 |
| V03 temporal fragmentation | 191 | 39.8% | LLM02 |

The other thirteen are in [docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md). Some of them barely
work — V11 social engineering lands 6.2% of the time, V19 model extraction 6.4%.
Those stay in the corpus because a vector that fails against every model is still
a data point about the models.

**6 multi-turn strategies**, up to 8 turns, with the attacker keeping session
memory:

| Strategy | n | Leak rate |
|----------|--:|----------:|
| escalation | 32 | 75.0% |
| language_rotation | 15 | 40.0% |
| gaslighting | 13 | 30.8% |
| rapport_to_extraction | 56 | 28.6% |
| context_overflow | 3 | 100.0% |
| persona_persistence | 3 | 66.7% |

Sorted by sample size, not by rate, because the bottom two are three runs each.
"context_overflow works 100% of the time" means it worked three times out of
three. Don't quote it.

**12 mutation strategies** for Iberian languages: Catalan, Basque, Galician, three
kinds of code-switching, formal and informal register, SMS abbreviations, academic
framing, authority framing, plain rephrasing.

**22 agentic seeds** across 5 of the 10 OWASP Agentic categories. Coverage is
partial and [documented as such](https://github.com/Gil910/Vigia/blob/main/docs/TAXONOMY.md#owasp-top-10-for-agentic-applications-2026):
nothing yet for supply chain compromise, unexpected code execution, cascading
failures, human-agent trust, or rogue agents. Cascading failures and rogue agents
need a multi-agent target that Vigia doesn't ship.

## What it gets wrong

Written up properly in [docs/METHODOLOGY.md](https://github.com/Gil910/Vigia/blob/main/docs/METHODOLOGY.md). The headlines:

The cross-model benchmark in `docs/RESULTS.md` was run with **llama3.1:8b as the
judge**, and one of the four targets in it is llama3.1:8b. A model scoring its own
output is 8.9 points more generous (23.0% vs 14.1% over the same 135 attacks), so
the Llama row is inflated and I would not defend the ordering of the top two.
Earlier versions of this README claimed the benchmark used Claude as judge. It
didn't. I found that re-deriving the tables from the database rather than trusting
what I'd written down, which is a decent argument for generating your results
tables from a script.

The target is a demo RAG app with three documents. Real deployments have
retrieval filters, output guardrails and rate limits that this doesn't model. No
NeMo Guardrails, no Llama Guard, no Azure Content Safety in the loop — these
numbers are what the models do bare.

The judge cache was keyed on the response text alone until v0.6.0, so 133 of the
2,769 results here (4.8%) may be false negatives — a turn inheriting an earlier
refusal's verdict because the chatbot happened to answer with the same words. Fixed
now, with a test. It puts the real overall rate somewhere between 37.1% and 41.9%
rather than exactly 37.1%. None of the affected results are Catalan, so the language
finding stands; if anything it is understated.

The corpus leans hard on exfiltration. Denial of wallet, model extraction and
supply chain each get a handful of seeds and correspondingly weak data.

The MITRE ATLAS column is the weakest thing in the repo. A third of the seeds carry
a technique that means intellectual property theft when what they actually do is
leak a salary. [docs/TAXONOMY.md](https://github.com/Gil910/Vigia/blob/main/docs/TAXONOMY.md#mitre-atlas)
says so in more detail. Use the OWASP column.

Runs aren't reproducible in the strict sense and I'd rather say so than pretend.
Temperature is above zero and API models change under you. What should reproduce
is the ordering, not the digits.

## Countermeasures

What I'd actually do, in the order I'd do it, based on what worked against the
demo target:

**Fix retrieval before you fix prompts.** V05 works because a chunk contains a
salary sitting next to something innocuous. Chunk by sensitivity level, not just
by token count, and attach an ACL to the chunk rather than to the document.
Everything else on this list is downstream of getting that wrong.

**Put the guardrail on the output, in the right language.** NeMo Guardrails or
Llama Guard on the response, with rules that exist in Spanish and Catalan. An
English-only rail is a rail with a 70% hole in it, which is the whole point of
this project.

**Watch for the shapes, not the keywords.** The vectors that work don't contain
banned words. A numerical anchor ("is it above or below 120k?"), a request for an
exhaustive summary, an inverted negation ("what are you not allowed to tell me?").
Those are patterns you can match on.

**For anything with tools**: least privilege by default, a human in the loop for
any write, delete or send, and treat tool output as untrusted input — a tool
result is a perfectly good prompt injection carrier (ASI01, ASI06).

**Cap the output.** V13 asks for the same full table five times. Length and query
complexity limits handle most of that.

## Roadmap

In rough priority order:

1. Re-run the cross-model benchmark with a judge that isn't one of the targets.
   Everything else is less interesting until this is done.
2. Multi-turn campaigns in Basque and Galician, to test whether those low rates
   are real resistance or a translation artefact.
3. Refresh the target list. The benchmark models (Llama 3.1 8B, Gemma2 2B,
   Mistral 7B) were current when I ran it in April 2026 and aren't any more.
4. Hand-validate a sample of eu/gl responses to quantify the judge's false
   negative rate in those languages.
5. Agentic coverage for the five empty ASI categories, which needs a multi-agent
   demo target first.

## Stack

Python 3.11+, Ollama for local models and LiteLLM for the commercial APIs (every
call goes through `vigia/providers.py`, which is the only place either is
imported). ChromaDB and LangChain for the demo RAG target. SQLite for results and
session memory. Rich for output.

## Prior art

[garak](https://github.com/NVIDIA/garak) and [PyRIT](https://github.com/Azure/PyRIT)
are the tools this borrows most from structurally.
[promptfoo](https://github.com/promptfoo/promptfoo) is the better choice if what
you want is regression testing in CI.
[Multilingual Jailbreak Challenges in LLMs](https://arxiv.org/abs/2310.06474)
(Deng et al., ICLR 2024) is the paper that started me down this road;
[Marx and Dunaiski 2026](https://arxiv.org/abs/2605.18239) is the one that made me
doubt my own Basque results.

## License

MIT. Use it on your own systems, or on systems you have permission to test.
Nothing else.
