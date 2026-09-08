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

2,432 attacks against five models in six Iberian locales, and then — because I
did not trust my own instrument — the same responses scored again by two more
judges, so I could tell which findings were about the models and which were about
whoever was grading them.

Three things came out of it. The third one killed the headline I had been sitting
on for five months.

### The reasoning leaks what the answer refuses to say

`deepseek-r1:8b` thinks before it replies. I captured that thinking, then scored
the same 233 responses twice: once on the final answer alone, once on the chain
of thought alone.

```
                        final answer    chain of thought
claude-haiku-4-5            18.5%            24.5%
gpt-5.6-luna                20.2%            28.3%
```

The model generated once and was judged twice, so none of that gap is run-to-run
noise. And the number I care about: **in 28 of the 233 attacks the final answer
was clean and the reasoning named the thing anyway** — 12% under Haiku, 36
attacks and 15.5% under the second judge.

If your application logs the reasoning block, or renders it in a "thinking…"
disclosure, those are leaks with nobody having successfully attacked anything.
The user sees a polite refusal. The log has the salary in it.

Both judges agree the effect exists; they overlap on only 18 of the 46 attacks
either of them flags, because a lot of these verdicts sit right on the scoring
threshold. So the honest form of the claim is a range, 12–15%, and not a list of
specific attacks.

### The retriever leaks more than the model does

The strongest vector in the corpus is `V05_passive_context_leak` at **71.7%**. Ask
something ordinary. The retriever pulls a chunk that happens to have a credential
two lines under the relevant text. The model reads out what it was handed. No
jailbreak, no injection, no adversarial phrasing at all.

Under the [OWASP 2026 list](https://genai.owasp.org/llm-top-10/) that is LLM09,
Vector and Embedding Weaknesses. It is a retrieval design problem, and no amount
of system-prompt hardening touches it.

### Catalan was not the soft spot, and finding that out is the useful part

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/language-leak-rate-dark.png">
    <img src="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/language-leak-rate.png" alt="Leak rate by locale, controlled for attack vector: Catalan 38.9%, Spanish 38.4%, Basque 28.8%, Spanish+Basque 27.7%, Galician 24.2%, Spanish+Galician 19.1%" width="820">
  </picture>
</p>

For most of 2026 this README said Catalan was 24 points more vulnerable than
Spanish. It said that because my Catalan corpus was one seed repeated across 76
campaigns, and that seed happened to be a numerical anchor, which is one of the
two strongest vectors I have. I was comparing a strong attack against a broad
mix and calling the difference a language effect.

With a balanced corpus — 39 seeds per locale, same 19 vectors everywhere — and
averaging each locale over the vectors they all share:

| Locale | Controlled leak rate |
|--------|---------------------:|
| ca-ES  | 38.9% |
| es-ES  | 38.4% |
| eu-ES  | 28.8% |
| es-EU  | 27.7% |
| gl-ES  | 24.2% |
| es-GL  | 19.1% |

Catalan and Spanish are the same. Three judges scoring the identical responses
disagree about which of the two goes first — Haiku says Catalan by 1.6 points,
gpt-5.6-luna says Spanish by 1.1, gemini-3.5-flash says Spanish by 2.7. When the
sign of a gap depends on who is grading, there is no gap.

**What does survive all three judges is the two-tier split.** Spanish and Catalan
cluster at the top; Basque, Galician and both code-switched locales sit 9 to 17
points below, and the bottom four keep almost exactly the same order under every
judge. That is the counterintuitive result, and it is the one I would defend.

I still don't fully believe the *explanation*. Lower-resource languages could
genuinely be harder for a model to be manipulated in, or the judge could just be
worse at reading them, and a leak it cannot read scores zero. Marx and Dunaiski
found something adjacent in [May 2026](https://arxiv.org/abs/2605.18239):
single-turn translated attacks fail in low-resource languages while multi-turn
ones succeed, and translation quality decides it. Mine are single-turn. That is
the next experiment, not a conclusion.

One thing points at "real, not artefact", though. Look back at the reasoning
finding: of the 28 attacks where the answer was clean and the reasoning leaked,
10 are Basque and 6 are Spanish–Basque, against 2 in Spanish. In the languages
that look safest, the model had already surfaced the sensitive data internally —
it just didn't say it out loud.

Full tables: **[docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md)**,
all of it generated from the database by a script. How the numbers are made and
where they break: **[docs/METHODOLOGY.md](https://github.com/Gil910/Vigia/blob/main/docs/METHODOLOGY.md)**.

## Why not just use garak or PyRIT

You probably should, alongside this. They cover far more ground. Vigia exists
because of three things they leave on the table:

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

Two scripts do the analysis, and everything published here comes out of them:

```bash
python scripts/stats.py results/vigia.db > docs/RESULTS.md   # every table
python scripts/rejudge.py --campaigns 3,4,5 --judge openai/… # score stored
python scripts/rejudge.py --campaigns 18 --arm reasoning     # responses again
```

`rejudge.py` is the one that made most of this possible. Generation is the
expensive half of a campaign and the boring half of most questions about the
judging, so it reads the stored responses back and scores them again — with a
different judge, or with the reasoning block stripped or isolated. Same
generations, so the only thing that moves is what you changed.

### Using it as a CI gate

`vigia scan` exits non-zero when it finds something above the threshold, and can
emit JUnit XML. One caveat, and it is not a small one: **gate on the aggregate
rate, never on a single seed.**

Running the same 233 seeds twice against the same model, with nothing changed,
flips 10.3% of individual verdicts for llama3.1:8b, 12.9% for gemma3:4b and 18.0%
for deepseek-r1:8b, while the aggregate rate moves by a point or less. The
reasoning model is the least reproducible of the three. A per-seed gate will be
flaky, and a flaky gate is a gate your team turns off.

## What it attacks

**19 RAG vectors**, 233 seeds across six locales, 39 per locale. The ones that
actually work, from the five-model benchmark:

| Vector | Attacks | Leak rate | OWASP 2026 |
|--------|--------:|----------:|------------|
| V05 passive context leak | 60 | 71.7% | LLM09 |
| V01 numerical anchor | 85 | 61.2% | LLM02 |
| V03 temporal fragmentation | 60 | 48.3% | LLM02 |
| V02 summary exfiltration | 60 | 41.7% | LLM02 |
| V12 training data extraction | 60 | 40.0% | LLM02 |
| V14 context window exploit | 60 | 38.3% | LLM01 |

The other thirteen are in [docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md).
Some of them barely work — V11 social engineering lands 8.3% of the time,
V07 cross-language confusion 11.7%. Those stay in the corpus because a vector
that fails against every model is still a data point about the models.

**Five models**, same seeds, same judge, one variable:

| Target | Leak rate |
|--------|----------:|
| llama3.1:8b | 14.2% |
| qwen3:8b | 16.7% |
| deepseek-r1:8b | 20.6% |
| gemma3:4b | 34.3% |
| mistral | 65.2% |

A second judge over the identical responses gives 14.6%, 14.6%, 18.5%, 36.9% and
70.0% — same ordering, except llama3.1 and qwen3 tie, and they were two points
apart to begin with. The largest disagreement between the two judges anywhere in
that table is 4.7 points.

**6 multi-turn strategies**, up to 8 turns, with the attacker keeping session
memory. Six conversations each, which is not many:

| Strategy | Runs | Leak rate |
|----------|-----:|----------:|
| escalation | 6 | 66.7% |
| persona_persistence | 6 | 33.3% |
| language_rotation | 6 | 16.7% |
| gaslighting | 6 | 16.7% |
| context_overflow | 6 | 16.7% |
| rapport_to_extraction | 6 | 0.0% |

Six is enough to say escalation is worth a look and not enough to rank the rest.
The samples are at least uniform now, which the April ones were not.

**12 mutation strategies** for Iberian languages: Catalan, Basque, Galician, three
kinds of code-switching, formal and informal register, SMS abbreviations, academic
framing, authority framing, plain rephrasing.

**22 agentic seeds** across 5 of the 10 OWASP Agentic categories, run three times
against the same agent: 10, 11 and 11 of 22 compromised, so 45–50%. Coverage is
partial and [documented as such](https://github.com/Gil910/Vigia/blob/main/docs/TAXONOMY.md#owasp-top-10-for-agentic-applications-2026):
nothing yet for supply chain compromise, unexpected code execution, cascading
failures, human-agent trust, or rogue agents. The last two need a multi-agent
target that Vigia doesn't ship.

## What it gets wrong

Written up properly in [docs/METHODOLOGY.md](https://github.com/Gil910/Vigia/blob/main/docs/METHODOLOGY.md).
The headlines, including the ones that are embarrassing:

**I published a language finding that was an artefact of my own corpus.** The
"+24 points for Catalan" claim rested on 80 attacks, 76 of which were the same
seed. I found it by writing a script that recomputes every table from the
database instead of trusting what I had written down. That script is
`scripts/stats.py`, everything in `docs/RESULTS.md` comes out of it, and it now
has its own tests, because it has been wrong twice and both times it failed by
printing a normal-looking table with a different number in it.

**My first cross-model benchmark used one of the targets as the judge.** A model
scoring its own output reports 6.0 points more leaks than a neutral judge on the
identical 233 responses. Pointing that same judge at a target that is *not*
itself adds 2.6, so roughly half of the inflation is general strictness and the
rest is specifically self-assessment. The whole September run uses a judge that
is none of the targets, and the numbers here are all from that.

**The second judge ran at a temperature I could not set.** `gpt-5.6-luna`
rejects an explicit temperature, so its verdicts came at the model's default and
are less repeatable than Haiku's, which ran at 0.1. Worth knowing when reading
any gap that involves it.

**The target is a demo RAG app with three documents.** Real deployments have
retrieval filters, output guardrails and rate limits that this doesn't model. No
NeMo Guardrails, no Llama Guard, no Azure Content Safety in the loop. These
numbers are what the models do bare, which is the point, but it is not what your
production stack does.

**The judge cache was keyed on the response text alone until v0.6.0**, so a turn
could inherit an earlier refusal's verdict because the chatbot happened to answer
with the same words. 38 of the 5,603 verdicts in the current database (0.7%) came
out of that cache, which puts the true overall rate between 28.0% and 28.7%. It
was 4.8% of the April results, and that is the reason those are not quoted here.

**A judge that dies halfway through does not announce it.** During the September
runs a free-tier quota ran out mid-campaign and 94 responses were scored by
counting keywords instead. They look exactly like verdicts in the database.
`stats.py` now drops them from every rate and names the campaigns they came from,
and the evaluator stops the run after five consecutive judge failures instead of
quietly degrading.

**The corpus leans hard on exfiltration.** Denial of wallet, model extraction and
supply chain each get a handful of seeds and correspondingly weak data.

**The MITRE ATLAS column is the weakest thing in the repo.** A third of the seeds
carry a technique that means intellectual property theft when what they actually
do is leak a salary.
[docs/TAXONOMY.md](https://github.com/Gil910/Vigia/blob/main/docs/TAXONOMY.md#mitre-atlas)
says so in more detail. Use the OWASP column.

**Runs are not reproducible in the strict sense** and I would rather say so than
pretend. Temperature is above zero, API models change under you, and the variance
numbers above say how much that costs. What should reproduce is the ordering, not
the digits.

## Countermeasures

What I would actually do, in the order I would do it, based on what worked against
the demo target:

**Fix retrieval before you fix prompts.** V05 works because a chunk contains a
salary sitting next to something innocuous. Chunk by sensitivity level, not just
by token count, and attach an ACL to the chunk rather than to the document.
Everything else on this list is downstream of getting that wrong.

**Treat the reasoning block as output.** If you deploy a reasoning model and you
log its chain of thought, ship it to an observability platform, or render it in
the UI, then it is part of your attack surface and it leaks in cases where the
answer does not. Redact it, or don't keep it.

**Put the guardrail on the output, in the right language.** NeMo Guardrails or
Llama Guard on the response, with rules that exist in Spanish and Catalan. An
English-only rail on a Spanish chatbot is a rail with a hole in it.

**Watch for the shapes, not the keywords.** The vectors that work don't contain
banned words. A numerical anchor ("is it above or below 120k?"), a request for an
exhaustive summary, an inverted negation ("what are you not allowed to tell me?").
Those are patterns you can match on.

**For anything with tools**: least privilege by default, a human in the loop for
any write, delete or send, and treat tool output as untrusted input — a tool
result is a perfectly good prompt injection carrier (ASI01, ASI02).

**Cap the output.** V13 asks for the same full table five times. Length and query
complexity limits handle most of that.

## Roadmap

In rough priority order:

1. Multi-turn campaigns in Basque and Galician. Six conversations per strategy is
   not a sample, and this is also the test of whether the low Basque and Galician
   rates are resistance or a translation artefact.
2. Hand-validate a sample of eu/gl responses to quantify the judge's false
   negative rate in those languages. Everything about the two-tier finding rests
   on the judges being able to read those languages.
3. Capture reasoning from more than one model. The chain-of-thought finding is
   one target, and one target is an anecdote with good error bars.
4. Agentic coverage for the five empty ASI categories, which needs a multi-agent
   demo target first.
5. A judge panel rather than a judge. Three judges disagreeing by a few points is
   information I currently throw away by picking one.

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
