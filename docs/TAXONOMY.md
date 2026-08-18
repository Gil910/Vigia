# Taxonomy mapping

Every seed carries an OWASP category and a MITRE ATLAS technique. Both OWASP lists
were renumbered in 2026 and this corpus was written against the older ones, so it
has been migrated. `scripts/remap_owasp_2026.py` is the whole migration: run it
against a pre-2026 corpus and you get the shipped one back. `scripts/validate_corpus.py`
checks the result in CI, against the same map, so a vector and its OWASP ID cannot
drift apart again without the build going red.

## OWASP GenAI LLM Top 10 (2026)

| ID | Category |
|----|----------|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Excessive Agency |
| LLM04 | Supply Chain |
| LLM05 | Data and Model Poisoning |
| LLM06 | Unbounded Consumption |
| LLM07 | Misinformation |
| LLM08 | Hidden Context Exposure |
| LLM09 | Vector and Embedding Weaknesses |
| LLM10 | Improper Output Handling |

### RAG vectors, old ID to new

| Vector | Was (2023 list) | Now (2026 list) | Why it moved |
|--------|-----------------|-----------------|--------------|
| V01 numerical anchor | LLM02 Insecure Output Handling | LLM02 Sensitive Information Disclosure | the number is the same, the category is not |
| V02 summary exfiltration | LLM02 | LLM02 | as above |
| V03 temporal fragmentation | LLM02 | LLM02 | as above |
| V04 inverse negation | LLM07 Insecure Plugin Design | LLM08 Hidden Context Exposure | it enumerates the policy text; it was never a plugin issue |
| V05 passive context leak | LLM02 | LLM09 Vector and Embedding Weaknesses | the failure is in the retriever, not the model |
| V06 role impersonation | LLM01 | LLM01 | unchanged |
| V07 cross-language confusion | LLM01 | LLM01 | unchanged |
| V08 chain-of-thought exploit | LLM06 Sensitive Info Disclosure | LLM02 | renumbering only |
| V09 compliant reformulation | LLM09 Overreliance | LLM02 | re-identifying "anonymised" data is disclosure |
| V10 indirect prompt injection | LLM01 | LLM01 | unchanged |
| V11 social engineering | LLM01 | LLM01 | unchanged |
| V12 training data extraction | LLM03 Training Data Poisoning | LLM08 Hidden Context Exposure | extraction, not poisoning; the old mapping had the arrow backwards |
| V13 resource exhaustion | LLM04 Model DoS | LLM06 Unbounded Consumption | renamed and renumbered |
| V14 context window exploit | LLM06 | LLM02 | renumbering |
| V15 excessive agency | LLM08 | LLM03 Excessive Agency | renumbering |
| V16 compound jailbreak | LLM01 | LLM01 | unchanged |
| V17 output manipulation | LLM09 Overreliance | LLM10 Improper Output Handling | an XSS payload in the response is an output handling bug |
| V18 supply chain trust | LLM05 | LLM04 Supply Chain | renumbering |
| V19 model extraction | LLM10 Model Theft | LLM06 Unbounded Consumption | Model Theft no longer exists as its own entry |

Eleven of the nineteen vectors changed ID. Three more (V01, V02, V03) kept LLM02
while LLM02 itself changed from Insecure Output Handling to Sensitive Information
Disclosure. So fourteen of nineteen were pointing at something that no longer means
what the corpus assumed. Only V06, V07, V10, V11 and V16 came through untouched,
because LLM01 is Prompt Injection in both lists.

If you are reading a Vigia report generated before v0.6.0, its OWASP column is
against the 2023 numbering.

### The `category` field

Each seed also has a `category` string, which is the snake_case form of its 2026
OWASP category. It used to hold the 2023 names, so seeds were labelled
`training_data_poisoning` under a category whose whole point is that it is
extraction rather than poisoning. The migration rewrites it alongside `owasp`, and
the validator enforces that the two agree.

### Coverage gaps

Two categories have no seeds at all:

- **LLM05 Data and Model Poisoning.** Poisoning a knowledge base is a supply-side
  attack. Vigia only ever talks to a target that is already deployed, so it can
  test the *effect* of a poisoned chunk (that is V10) but not the poisoning.
- **LLM07 Misinformation.** Out of scope by design. Vigia scores information
  leakage, not factual accuracy. Measuring misinformation needs ground truth the
  framework does not have.

Neither is on the roadmap. Better to say so than to pad the coverage table.

## OWASP Top 10 for Agentic Applications (2026)

| ID | Category | Vigia seeds |
|----|----------|:-----------:|
| ASI01 | Agent Goal Hijack | 5 |
| ASI02 | Tool Misuse & Exploitation | 9 |
| ASI03 | Agent Identity & Privilege Abuse | 6 |
| ASI04 | Agentic Supply Chain Compromise | 0 |
| ASI05 | Unexpected Code Execution | 0 |
| ASI06 | Memory & Context Poisoning | 1 |
| ASI07 | Insecure Inter-Agent Communication | 1 |
| ASI08 | Cascading Agent Failures | 0 |
| ASI09 | Human-Agent Trust Exploitation | 0 |
| ASI10 | Rogue Agents | 0 |

22 seeds across 5 of 10 categories.

The previous mapping used a four-item draft in which ASI04 meant "excessive agency"
and ASI05/ASI06 meant "inadequate sandboxing". In the published list ASI04 is
Agentic Supply Chain Compromise, ASI05 is Unexpected Code Execution and ASI06 is
Memory & Context Poisoning. Nothing about that was a renumbering; the categories
are different. The five old ASI04 seeds went to ASI02, except `feature_flag_abuse`,
which is really privilege abuse and went to ASI03.

Information disclosure by an agent has no home in the agentic list. Where the
agentic evaluator used to emit "ASI06: Inadequate Sandboxing" for it, it now emits
LLM02 from the LLM list, which is where that risk actually lives.

The empty rows are the honest state of the agentic module: it covers the
single-agent attack surface reasonably and the multi-agent one barely at all.
ASI08 and ASI10 need a multi-agent target that Vigia does not ship yet.

## MITRE ATLAS

Every seed carries an `atlas` technique ID. 390 of the 412 do; the mutated variants
inherit theirs from the seed they came from.

| Technique | Seeds |
|-----------|------:|
| AML.T0048.004 | 130 |
| AML.T0051.000 | 40 |
| AML.T0054.000 | 20 |
| AML.T0051.001 | 20 |
| AML.T0043.003 | 20 |
| ten others | 20 each |

**This is the weakest mapping in the project and I would not cite it.** Three
problems, in order of how much they bother me:

The most-used technique, `AML.T0048.004`, is *AI Intellectual Property Theft*, an
External Harms sub-technique. It is on 130 seeds whose actual job is to make a
chatbot read out a salary or an SSH key. Data leakage and IP theft are not the same
harm, and a third of the corpus says they are.

`AML.T0051` (Prompt Injection, the parent) is on V10, the indirect injection vector,
while `AML.T0051.001` (the *Indirect* sub-technique) is on V16, compound jailbreak.
Those two are the wrong way round.

The OWASP migration moved several vectors to categories their ATLAS technique does
not sit comfortably under. V19 carries `AML.T0044` (Full AI Model Access) beneath
LLM06 Unbounded Consumption, because 2026 has nowhere better to put model theft.
V12 carries `AML.T0024` (Exfiltration via AI Inference API) beneath LLM08 Hidden
Context Exposure, which is about the context window rather than the training data.

Fixing this properly means re-reading every seed against the current ATLAS matrix,
which shipped 45+ new techniques and sub-techniques in its 2026 update, a good chunk
of them agentic. That is a piece of work, not a find-and-replace, and it has not
been done. Until it is, treat the OWASP column as the load-bearing one and the ATLAS
column as a hint.
