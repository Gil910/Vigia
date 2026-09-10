# Security policy

## What this tool is for

Vigia generates and fires attack prompts at LLM systems. Point it at something you
own, or something you have written permission to test. That is the whole rule.

The bundled RAG chatbot under `vigia/targets/rag_victim/` exists so you can run the
tool end to end without touching anything real. Its "sensitive" documents are made
up: TechCorp España does not exist, and neither do its salaries, its SSH keys, or
its committee minutes.

If you use Vigia against a third-party service without authorisation, that is on
you, and depending on where you are it is probably a crime. In Spain, see article
197 bis of the Código Penal.

## Reporting a vulnerability in Vigia itself

Open a GitHub issue for anything that is not itself exploitable. For something
that is (say, a path traversal in the config loader, or a way to make Vigia leak
your API keys), email jordigiln@gmail.com instead and give me a couple of weeks
before publishing.

## API keys

Vigia never writes credentials to disk. It reads `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY` and friends from the environment and hands them to LiteLLM.
Campaign results in `results/vigia.db` do contain full prompts and full target
responses, so if you test a real system that database holds whatever your system
leaked. Treat it accordingly. It is gitignored for that reason.
