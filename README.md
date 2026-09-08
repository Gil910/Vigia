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

1,912 attacks against five models in six Iberian locales, and then, because I did
not trust my own instrument, the same responses scored again by two more judges.
That was so I could tell which findings were about the models and which were
about whoever was grading them.

Two findings held up. A third one did not, and the reason it did not is the part
of this repo I would actually point a hiring manager at.

### The reasoning leaks what the answer refuses to say

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/reasoning-leak-dark.png">
    <img src="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/reasoning-leak.png" alt="deepseek-r1:8b, 181 attacks judged twice. Final answer leaks 23.8% under Claude Haiku and 26.0% under gpt-5.6-luna; the chain of thought leaks 30.4% and 35.4%. In 26 and 34 attacks the answer was clean and the reasoning was not." width="820">
  </picture>
</p>

`deepseek-r1:8b` thinks before it replies, and that thinking comes back in a
field of its own. I captured it and scored the same 181 responses twice: once on
the final answer alone, once on the chain of thought alone.

The model generated once and was judged twice, so none of that gap is run-to-run
noise. The number I care about is the last column: **in 26 of 181 attacks the
final answer was clean and the reasoning named the thing anyway.** That is 14.4%
under Haiku, and 34 attacks — 18.8% — under the second judge.

If your application logs the reasoning block, ships it to an observability
platform, or renders it in a "thinking…" disclosure, those are leaks with nobody
having successfully attacked anything. The user sees a polite refusal. The log
has the salary in it.

Both judges agree the effect is there. They overlap on 18 of the 42 attacks
either of them flags, because a lot of these verdicts sit right on the scoring
threshold. So the honest form of the claim is a range, 14–19%, and not a list of
particular attacks.

One target, one architecture. Any model with a separate reasoning field would
extend it, and that is [an open issue](https://github.com/Gil910/Vigia/issues).

### The retriever leaks more than the model does

The strongest vector in the corpus is `V05_passive_context_leak` at **70.9%**. Ask
something ordinary. The retriever pulls a chunk that happens to have a credential
two lines under the relevant text. The model reads out what it was handed. No
jailbreak, no injection, no adversarial phrasing at all.

Under the [OWASP 2026 list](https://genai.owasp.org/llm-top-10/) that is LLM09,
Vector and Embedding Weaknesses. It is a retrieval design problem, and no amount
of system-prompt hardening touches it.

### The language finding: two corpus bugs, one lesson

For most of 2026 this README said Catalan was 24 points more vulnerable than
Spanish. That was wrong, and it was wrong because my Catalan corpus was a single
seed covering 76 of its 80 attacks, and that seed was a numerical anchor — one of
the two strongest vectors I have. I was comparing a strong attack against a broad
mix and calling the difference a language effect.

So I balanced the corpus, re-ran everything, and got a smaller but tidy result:
Spanish and Catalan level at the top, Basque and Galician 9 to 17 points below,
holding under all three judges. I wrote that up. It was going to be the third
finding in a launch post.

Then I read my own corpus.

Fifty-two of the 233 seeds were not attacks. They were the mutation model
declining to translate, saved into the corpus as if the refusal were the prompt.
Fifteen of them read, in full, `Lo siento, pero no puedo cumplir con esa
solicitud.` One still had the mutator's own instructions in it: *"my job is to
translate the given prompt into Batua Basque."*

A seed like that cannot leak anything. It scores zero whatever the target does.
And they were not spread evenly — 19 in Galician, 13 in Basque, 3 in Catalan,
**none at all in Spanish**, which is the same shape as the finding they were
producing.

With those rows out, and a bootstrap over the seeds within each vector:

| | gap between the tiers | 95% interval |
|---|---:|---|
| as published, Claude Haiku | 9.6 points | 1.9 to 13.2 |
| dead seeds removed, Claude Haiku | **4.2 points** | **−2.2 to 8.0** |
| as published, gpt-5.6-luna | 10.7 points | 3.2 to 15.3 |
| dead seeds removed, gpt-5.6-luna | **4.6 points** | **−2.4 to 9.1** |

The interval crosses zero under both judges. And the surviving Galician sample is
20 seeds over 5 vectors, which is not enough to compare against Spanish at all —
`scripts/stats.py` now refuses to put those locales in the table rather than
printing a number that looks like the others.

**So I have no language finding.** Not "a smaller one": none. The same class of
bug bit the same claim twice, in opposite directions, and the second time it took
the whole thing with it.

What I do have is the mechanism, the detector, and a corpus that fails CI if it
ever happens again — `vigia mutate` retries when the model refuses and drops the
mutation rather than storing it, and `scripts/validate_corpus.py` fails on one.
Regenerating those 52 seeds and re-running the benchmark would give the language
question a real answer. That is the top open item, not a footnote.

Full tables: **[docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md)**,
all of it generated from the database by a script. How the numbers are made and
where they break: **[docs/METHODOLOGY.md](https://github.com/Gil910/Vigia/blob/main/docs/METHODOLOGY.md)**.

## Why not just use garak or PyRIT

You probably should, alongside this. They cover far more ground. Vigia exists
because of three things they leave on the table:

- Attacks written *in* Spanish, Catalan, Basque and Galician, rather than English
  probes machine-translated at run time. Whether translation quality changes the
  result is exactly the question I could not answer above, and machine-translating
  at run time makes it unanswerable.
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

Three scripts do the analysis, and everything published here comes out of them.
They live in the repository, not in the wheel, so this part needs a clone:

```bash
python scripts/stats.py results/vigia_2026-09.db > docs/RESULTS.md  # every table
python scripts/rejudge.py --campaigns 3,4,5 --judge openai/…  # score the stored
python scripts/rejudge.py --campaigns 5 --arm reasoning       # responses again
python scripts/validate_corpus.py                             # before you trust it
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

Running the same 181 seeds twice against the same model, with nothing changed,
flips 11.6% of individual verdicts for llama3.1:8b, 16.0% for gemma3:4b and 22.1%
for deepseek-r1:8b, while the aggregate rate moves by a point or less. The
reasoning model is the least reproducible of the three. Gate on a per-seed
assertion and the pipeline will be flaky, and nobody keeps a flaky gate for long.

## What it attacks

**19 RAG vectors** over 233 seeds in six locales, of which 181 are usable — the
other 52 are the dead ones described above, and the numbers here are over the
181. The vectors that actually work, from the five-model benchmark:

| Vector | Attacks | Leak rate | OWASP 2026 |
|--------|--------:|----------:|------------|
| V05 passive context leak | 55 | 70.9% | LLM09 |
| V01 numerical anchor | 85 | 61.2% | LLM02 |
| V09 compliant reformulation | 35 | 51.4% | LLM01 |
| V03 temporal fragmentation | 60 | 48.3% | LLM02 |
| V02 summary exfiltration | 55 | 45.5% | LLM02 |
| V12 training data extraction | 55 | 43.6% | LLM08 |
| V14 context window exploit | 50 | 42.0% | LLM02 |

The other twelve are in [docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md).
Some of them barely work — V11 social engineering lands 5.7% of the time,
V18 supply chain trust 10.0%. Those stay in the corpus because a vector that
fails against every model is still a data point about the models.

**Five models**, same seeds, same judge, one variable:

| Target | Leak rate |
|--------|----------:|
| llama3.1:8b | 17.1% |
| qwen3:8b | 21.5% |
| deepseek-r1:8b | 25.4% |
| gemma3:4b | 43.1% |
| mistral | 70.2% |

A second judge over the identical responses gives 17.7%, 18.8%, 22.1%, 46.4% and
76.8%: the same ordering, with the two judges never more than 6.6 points apart
and that widest disagreement on mistral, the model they both put last anyway.

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

**I published a language finding that was an artefact of my own corpus, twice.**
The "+24 points for Catalan" claim rested on 80 attacks, 76 of which were the
same seed. The two-tier claim that replaced it rested on a corpus where a fifth
of the seeds were the mutation model's refusals, none of them in Spanish. Both
times the table looked completely normal. Both times what caught it was
recomputing everything from the database rather than trusting my notes —
`scripts/stats.py`, which now has its own tests, and `scripts/validate_corpus.py`,
which now reads the prompts rather than just their schema.

**My first cross-model benchmark used one of the targets as the judge.** A model
scoring its own output reports 7.2 points more leaks than a neutral judge on the
identical 181 responses. Pointing that same judge at a target that is *not*
itself adds 2.2, so about a third of the inflation is general strictness and the
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
with the same words. None of the five benchmark campaigns hit that cache — the
table in `docs/RESULTS.md` says 0 of 905 — but 4.8% of the April results did,
which is why those are not quoted here.

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

1. Regenerate the 52 dead seeds and re-run the benchmark. Until that happens
   there is no language comparison at all, and Galician is down to 20 usable
   seeds. `scripts/fix_seeds.py` does the first half.
2. Hand-validate a sample of eu/gl responses to quantify the judge's false
   negative rate in those languages. A leak the judge cannot read scores zero,
   and no amount of re-running fixes that.
3. Capture reasoning from more than one model. The chain-of-thought finding is
   one target, and one target is an anecdote with good error bars.
4. Multi-turn campaigns in Basque and Galician. Six conversations per strategy is
   not a sample.
5. Agentic coverage for the five empty ASI categories, which needs a multi-agent
   demo target first.
6. A judge panel rather than a judge. Three judges disagreeing by a few points is
   information I currently throw away by picking one.

## Stack

Python 3.11+, Ollama for local models and LiteLLM for the commercial APIs. Almost
every call goes through `vigia/providers.py`; `vigia/agents/target.py` still
reaches for both directly, which is a wart I have not paid off. ChromaDB and
LangChain for the demo RAG target. SQLite for results and session memory. Rich
for output.

## Prior art

[garak](https://github.com/NVIDIA/garak) and [PyRIT](https://github.com/Azure/PyRIT)
are the tools this borrows most from structurally.
[promptfoo](https://github.com/promptfoo/promptfoo) is the better choice if what
you want is regression testing in CI.
[Multilingual Jailbreak Challenges in LLMs](https://arxiv.org/abs/2310.06474)
(Deng et al., ICLR 2024) is the paper that started me down this road;
[Marx and Dunaiski 2026](https://arxiv.org/abs/2605.18239) is the one that made me
doubt my own Basque results before the corpus did.

## License

MIT. Use it on your own systems, or on systems you have permission to test.
Nothing else.
