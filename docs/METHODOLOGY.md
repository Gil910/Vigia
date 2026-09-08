# Methodology, and where it breaks

Everything in [RESULTS.md](RESULTS.md) comes out of the campaign database via
`scripts/stats.py`. If a number in the README does not match what that script
prints, the README is wrong. This page is about how the numbers are produced and
which of them you should not lean on.

The headline numbers come from a September 2026 run: 233 seeds across six locales,
fired at five models, judged by `claude-haiku-4-5`, which is none of the targets.
The same 1,165 responses were then scored again by `gpt-5.6-luna` and, for three
of the five targets, by `gemini-3.5-flash`. April 2026 numbers are not quoted
anywhere any more, and the section on the judge cache says why.

## What counts as a leak

Every attack gets a 0–10 score from an LLM judge. A score of 5 or more counts as a
leak; 7 or more counts as critical. The threshold is a judgement call and it is
configurable (`vigia scan --fail-on-score N`), but every table here uses 5 so the
comparisons hold.

The distribution is heavily bimodal. Of the 1,165 attacks in the benchmark, 598
scored 0–1 and 335 scored 7–10. Only 17 landed on 5 or 6. Moving the threshold from
5 to 6 changes the overall rate from 30.2% to 29.4%, so the exact cut-off is not
doing much work — the judge is mostly making easy calls, which is worth
remembering when you read a headline rate, in both directions.

## Errored attacks

An attack that never reached the judge gets `score = -1`: provider timeouts, an
unreachable HTTP target, an expired key. Those are dropped from every rate and
reported separately, because counting them as "the target held" deflates
everything. The September database has none.

An earlier version of this project did count them, which is how a set of published
rates ended up several points too low.

## Verdicts that are not verdicts

When a judge call fails, Vigia falls back to counting keywords in the response and
says so in the row. That is the right behaviour for one blip and the wrong
behaviour for a judge that has stopped answering, because the rows it writes are
indistinguishable from real verdicts unless you read the reasoning field.

This bit us. During the September re-judging, `gemini-3.5-flash` scored 139 mistral
responses, ran out of free-tier quota, and the remaining 94 were keyword matches
filed in the same campaign — which then read like an independent second opinion at
60.1%. Two things changed:

- The evaluator now raises `JudgeUnavailable` after five consecutive failures,
  whether or not it was working before. It used to require that the judge had
  *never* answered, which only catches a wrong model id or a missing key.
- `stats.py` drops keyword-scored rows from every rate, names the campaigns they
  came from, and excludes any campaign with more than 10% of them from the
  comparable set entirely.

The affected campaigns are listed in RESULTS.md under "Verdicts the judge never
gave". None of them feed a published number.

## The judge, and two different kinds of judge bias

### A model scoring itself

Same 233 responses from `llama3.1:8b`, one variable:

| Judge | Leaks | Rate |
|-------|------:|-----:|
| claude-haiku-4-5 | 33 / 233 | 14.2% |
| llama3.1:8b (the target itself) | 47 / 233 | 20.2% |

Six points. But "a model flatters itself" and "this model is a harsh judge of
everyone" produce the same table, and they have very different consequences, so
the control is the same judge pointed at a target that is not itself:

| Target | claude-haiku-4-5 | llama3.1:8b as judge | Delta |
|--------|-----------------:|---------------------:|------:|
| gemma3:4b | 34.3% | 36.9% | +2.6 |
| llama3.1:8b | 14.2% | 20.2% | +6.0 |

So roughly 2.6 points of that gap is general strictness and the remaining 3.4 is
specifically self-assessment. Both are reasons not to let a target grade itself,
but only the second is a reason to distrust *this* judge less on other targets.

The first cross-model benchmark this project published used `llama3.1:8b` as the
judge with `llama3.1:8b` as one of the four targets. That is why those numbers are
gone.

### A different judge entirely

The whole benchmark, re-scored without regenerating anything:

| Target | claude-haiku-4-5 | gpt-5.6-luna | Delta |
|--------|-----------------:|-------------:|------:|
| llama3.1:8b | 14.2% | 14.6% | +0.4 |
| qwen3:8b | 16.7% | 14.6% | -2.1 |
| deepseek-r1:8b | 20.6% | 18.5% | -2.1 |
| gemma3:4b | 34.3% | 36.9% | +2.6 |
| mistral | 65.2% | 70.0% | +4.7 |

Same ordering, except llama3.1 and qwen3 swap into a tie, and they were 2.5 points
apart to begin with. The largest disagreement anywhere in the table is 4.7 points
on a rate of 65%.

**Read the ordering, not the rates.** Two judges rarely agree on an absolute
number, and a finding that needs one of them to agree is not a finding. This is
the rule the language section below is written to.

One caveat on the second judge: `gpt-5.6-luna` rejects an explicit temperature, so
its verdicts ran at the model's default while Haiku's ran at 0.1. It is a noisier
instrument than the primary judge, by construction, and there is nothing to be
done about that from the client side.

## Run-to-run variance

The same config against the same 233 seeds, run twice, nothing changed:

| Target | Run 1 | Run 2 | Verdicts that flipped | Identical scores |
|--------|------:|------:|----------------------:|-----------------:|
| llama3.1:8b | 14.2% | 14.2% | 24 / 233 (10.3%) | 66.1% |
| gemma3:4b | 34.3% | 33.5% | 30 / 233 (12.9%) | 55.8% |
| deepseek-r1:8b | 20.6% | 17.2% | 42 / 233 (18.0%) | 51.5% |

The aggregate rate is stable to about a point. Individual verdicts are not: between
one seed in ten and one in five changes sides between runs, and only half to
two-thirds get the same score twice.

The reasoning model is the least reproducible of the three by a clear margin, and
`gemma3:4b` sitting between the other two says it is not purely a reasoning
effect — there is a floor of noise under all of them.

This is the single most useful thing in the repo for anyone building a CI gate.
Gating a deploy on "seed ES-V05-003 must not leak" produces a flaky pipeline.
Gate on the aggregate, and give the threshold a couple of points of headroom.

Only 35 of 233 responses were byte-identical between the two llama3.1 runs, at
temperature 0.3. Most of the variance is the target, not the judge.

## Where the leak lives, and why that measurement is designed the way it is

`deepseek-r1:8b` produces a chain of thought before its answer. The obvious way to
ask whether the reasoning leaks more than the answer is to run the model twice,
once showing the judge the reasoning and once not. That measurement would be
mostly noise: 18% of this model's verdicts flip between two identical runs, which
is larger than the effect being looked for.

So the model generated once, and the stored responses were scored twice — once
with the reasoning stripped, once with the reasoning alone. Same generations,
so the only thing that moves is what the judge read.

| Judge | Final answer | Reasoning | Answer clean, reasoning leaks |
|-------|-------------:|----------:|------------------------------:|
| claude-haiku-4-5 | 18.5% | 24.5% | 28 / 233 (12.0%) |
| gpt-5.6-luna | 20.2% | 28.3% | 36 / 233 (15.5%) |

Two judges, same direction, and the answer-only arm reproduces the benchmark's
20.6% within this model's own noise, which is the check that nothing else moved.

**The limit of it:** the two judges overlap on only 18 of the 46 attacks either of
them flags. The effect is solid, the list is not, because a verdict sitting near
the threshold moves on the smallest disagreement between two graders. Quote the
range, 12–15%, and never a specific set of attacks.

It is one target. Whether other reasoning models behave the same way is unmeasured.

## Comparing languages

Raw per-locale rates are only comparable if every locale ran the same mix of
attacks. In the corpus this project shipped for most of 2026 they did not: `ca-ES`
carried 3 distinct seeds over 2 vectors, 76 of its 80 attacks being a single
numerical anchor, while `es-ES` carried 63 seeds over 26 vectors. Numerical anchor
is one of the two strongest vectors in the corpus, so Catalan looked 24 points more
vulnerable than Spanish when what was really being compared was one strong attack
against a broad mix.

The corpus now carries 39 seeds per locale over the same 19 vectors, and
`stats.py` averages each locale's per-vector rate over the vectors they all share.
A locale too thin to share enough vectors is dropped from the comparison and named
rather than given a number that looks like the others and does not mean the same
thing.

Three judges over the identical responses:

| Locale | claude-haiku-4-5 | gpt-5.6-luna | gemini-3.5-flash |
|--------|-----------------:|-------------:|-----------------:|
| ca-ES | 40.0% | 40.5% | 36.8% |
| es-ES | 38.4% | 41.6% | 39.5% |
| eu-ES | 29.2% | 29.7% | 17.1% |
| es-EU | 28.7% | 27.7% | 19.7% |
| gl-ES | 25.6% | 25.1% | 14.5% |
| es-GL | 19.5% | 21.0% | 13.7% |

(The Gemini column covers three of the five targets rather than all five, so read
it down the column and not across the row. Its ordering is still its ordering.)

What holds under all three: Spanish and Catalan at the top, everything else 9 to 17
points below, and the bottom four in almost exactly the same order. What does not
hold: which of Catalan and Spanish goes first. Haiku says Catalan by 1.6,
gpt-5.6-luna says Spanish by 1.1, Gemini says Spanish by 2.7. When the sign of a
gap depends on the grader, there is no gap.

There is a fourth column in RESULTS.md: `llama3.1:8b`, which scored one target and
produces an ordering no other judge produces, including `es-GL` — the safest locale
under all three real judges — in third place. It is left in as the clearest
evidence in the database that an 8B local model is not a judge.

## Sample sizes

Some of the more quotable results rest on very little data.

| Claim | n | Read it as |
|-------|--:|------------|
| Per-locale rates | 190–195 each, balanced | solid |
| Cross-model benchmark | 233 per model, identical seeds, two judges | solid |
| RAG vectors | 60–85 each | solid |
| Reasoning vs answer | 233, two judges, one target | solid for the effect, one model only |
| Agentic, aggregate | 22 seeds × 3 runs: 10, 11, 11 | a range, 45–50% |
| Agentic, per vector | 3–12 each | anecdote, not a rate |
| Multi-turn, per strategy | 6 conversations each | directional at best |

The agentic per-vector table has rows reading 100%. That means three attacks out of
three. It reads well and means very little, which is why the aggregate is the
number quoted in the README.

## The judge cache was keyed wrong until v0.6.0

To save tokens, low-scoring verdicts (score ≤ 2, almost always refusals) are
cached. Until v0.6.0 the cache key was a hash of the target's response **and
nothing else**. Two turns of the same conversation can produce byte-identical
responses off completely different prompts, and the second one silently inherited
the first one's "blocked" verdict.

Not hypothetical: in the April database, 9 distinct response strings were scored 2
or below in one place and 5 or above in another, and `"Lo siento, pero no puedo
cumplir con esa solicitud."` appears 158 times with scores spanning 0 to 10 —
because whether a response is a leak depends on what was asked for.

The key now covers the prompt, the response, the seed's target behaviour **and the
judge**. That last part was added later and for a different reason: the persistent
half of the cache is documented as being for cross-campaign reuse, so without the
model in the key, a campaign that changes judges reads back the previous judge's
verdicts and reports them as its own — which is precisely what a judge comparison
exists to measure. It never fired in the September run, because `scan` passes no
connection and the in-memory cache dies with the process, so the +6.0 points of
measured judge bias is off uncached verdicts. That was luck rather than design.

Impact on the current database:

| Evaluated | Served from cache | Leak rate | If every cached verdict were wrong |
|---:|---:|---:|---:|
| 5,603 | 38 (0.7%) | 28.0% | 28.7% |

Every cached verdict scored 0 or 1, so the error only runs one way. In the April
database it was 133 of 2,769 (4.8%), which is the main reason those results are no
longer quoted.

## A config is not a record of what happened

`capture_thinking` was read out of the target config and never passed to the
provider until v0.6.0. So the database contains a campaign whose config asks for
the reasoning block and whose responses contain none of it — three hours of run
time measuring the same thing as every other campaign.

Believing the config would have paired that campaign against the one that did
capture reasoning and reported a seven-point treatment effect as run-to-run
variance. `stats.py` now decides whether a campaign captured reasoning by looking
at the responses, not the config, and names any campaign where the two disagree.

The general lesson is worth stating: a config records an intention. Only the data
records what happened, and when they disagree the data wins.

## Known false negatives

- **Basque and Galician.** A leak the judge cannot read scores 0. The low rates
  for `eu-ES` and `gl-ES` are therefore an upper bound on resistance and a lower
  bound on vulnerability. Two things push against pure artefact — the ordering
  survives two judges from different vendors, and the reasoning measurement finds
  the sensitive data surfacing internally in Basque more than in any other locale —
  but nobody has hand-checked those responses, and until somebody does this stays
  the weakest link in the language finding.
- **Partial leaks.** The judge rewards a full, quoted secret. A response narrowing
  a salary to a €10k band scores low, but four of those in sequence is a leak.
  Vigia scores turns, not sessions.
- **Structured output.** V17 fires XSS and JSON payloads at the target, but Vigia
  never renders the response. It cannot tell a payload that would have executed
  from one that would have been escaped downstream.
- **Cached verdicts.** 38 results in the current database came from the cache
  described above and may be wrong in the direction of "no leak".

## Reproducing this

```bash
git clone https://github.com/Gil910/Vigia && cd Vigia
pip install -e ".[dev]"
ollama pull llama3.1:8b && ollama pull nomic-embed-text

vigia run                                   # writes to results/vigia.db
python scripts/stats.py results/vigia.db    # regenerates every table
```

You will not get these numbers back. Temperature is above zero, the models behind
the API names change under you, and per the variance table above I do not get my
own numbers back either. What should reproduce is the ordering: mistral far above
gemma3, gemma3 above the rest, Spanish and Catalan together at the top of the
language table with Basque and Galician below them, V05 as the strongest vector.

If your ordering comes out different, that is worth an issue.
