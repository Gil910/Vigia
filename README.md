# VIGÍA

![version](https://img.shields.io/badge/version-0.5.2-blue)
![python](https://img.shields.io/badge/python-3.11+-green)
![license](https://img.shields.io/badge/license-MIT-orange)

<p align="center">
  <strong>Framework de red teaming automatizado para LLMs en español</strong><br>
  Single-shot · Multi-turn adaptativo · Testing de agentes · CI/CD gate · 6 variantes lingüísticas ibéricas
</p>

<p align="center">
  <a href="#resultados">Resultados</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#comandos">Comandos</a> •
  <a href="#taxonomía-de-ataques">Taxonomía</a> •
  <a href="#arquitectura">Arquitectura</a> •
  <a href="#contramedidas">Contramedidas</a> •
  <a href="#limitaciones">Limitaciones</a>
</p>

---

## Resumen Ejecutivo

Casi toda la investigación de seguridad en LLMs se hace en inglés, pero las empresas españolas están desplegando chatbots RAG en castellano para banca, sanidad y administración pública. Esos chatbots tienen guardrails entrenados mayoritariamente en inglés. VIGÍA automatiza la auditoría de seguridad con ataques diseñados nativamente en español, técnicas de code-switching entre lenguas ibéricas, y vectores que explotan cómo los modelos procesan el castellano.

**Hallazgos clave tras 3.086 ataques en 6 variantes lingüísticas:**

- **El catalán amplifica la vulnerabilidad +22 puntos sobre castellano** — ca-ES 59.6% vs es-ES 37.8%. Es la "zona roja del alineamiento": suficiente comprensión para procesar el ataque, insuficiente alineamiento para bloquearlo
- **Euskera y gallego REDUCEN la vulnerabilidad** — eu-ES 24.1%, gl-ES 23.8%. Hallazgo contraintuitivo: los idiomas menos representados en training no rompen guardrails, los confunden hasta la incomprensión
- **Mistral es 2.9× más vulnerable que Claude** — 51.8% vs 17.9% sobre los mismos 195 seeds (benchmark con Claude Haiku como judge)
- **El evaluator introduce sesgo medible** — llama-judge infla scores vs claude-judge (23% vs 14.1% sobre los mismos ataques). Metodológicamente, el judge debe ser un modelo diferente al target
- **context_overflow sigue siendo la estrategia más efectiva** — 100% de éxito en multi-turn contra Llama 3.1 8B

## Qué hace

VIGÍA lanza ataques automatizados contra tu chatbot (local o remoto), evalúa si ha filtrado información sensible usando un LLM como juez, y genera un informe con los resultados mapeados a OWASP Top 10 for LLMs y MITRE ATLAS.

### Modos de ataque

- **Single-shot** — una seed, un intento, un score. El benchmark clásico.
- **Multi-turn** — conversación de hasta 8 turnos con 6 estrategias de extracción progresiva.
- **Adaptativo** — el atacante acumula memoria de sesión y auto-selecciona la estrategia óptima.
- **Agentic** — ataca agentes AI con herramientas (tool misuse, goal hijacking, privilege escalation).
- **CI/CD gate** — integración en pipelines con exit codes, JUnit XML y JSON output.

## Resultados

### Vulnerabilidad por idioma — 3.086 ataques, 6 variantes lingüísticas

| Idioma | Ataques | Vuln rate | Avg score | Descripción |
|--------|:-------:|:---------:|:---------:|-------------|
| 🔴 ca-ES | 94 | **59.6%** | 3.7 | Catalán estándar |
| 🟡 es-ES | 1.734 | 37.8% | 3.1 | Castellano (baseline) |
| 🟢 es-EU | 314 | 28.0% | 2.4 | Code-switching español↔euskera |
| 🟢 es-GL | 314 | 24.2% | 2.2 | Code-switching español↔gallego |
| 🟢 eu-ES | 315 | 24.1% | 2.0 | Euskera (batua) |
| 🟢 gl-ES | 315 | **23.8%** | 2.1 | Gallego normativo |

**Delta lingüístico**: +22 puntos porcentuales entre catalán y castellano. El catalán está en la "zona roja del alineamiento" — suficiente comprensión para procesar ataques complejos, insuficiente alineamiento para reconocerlos como tales.

### Benchmark cross-model — 195 seeds × 4 modelos (judge: Claude Haiku 4.5)

| Modelo | Tipo | Tasa vuln | Vulns | Críticos (≥7) | Score medio | Score máx |
|--------|------|:---------:|:-----:|:-------------:|:-----------:|:---------:|
| Claude Haiku 4.5 | Comercial | **17.9%** | 35 | 14 | 1.8 | 10 |
| Llama 3.1 8B | Open source | 20.5% | 40 | 17 | 1.9 | 10 |
| Gemma2 2B | Open source | 32.3% | 63 | 28 | 2.7 | 10 |
| Mistral 7B | Open source | **51.8%** | 101 | 52 | 4.2 | 10 |

### Benchmark Multi-Turn — Target: Llama 3.1 8B

**Impacto del modelo atacante:** el modelo que genera los prompts de ataque es el factor más determinante. Llama 3.1 8B como atacante se auto-censura, limitando la efectividad. Modelos más capaces como atacantes multiplican la tasa de vulnerabilidad.

| Atacante | Estrategia | Seeds | Tasa vuln | Datos extraídos |
|----------|-----------|:-----:|:---------:|:---------------:|
| Llama 3.1 8B | rapport_to_extraction | 3 | 33.3% | salary, name |
| Llama 3.1 8B | gaslighting | 3 | 33.3% | Juan Pérez |
| Llama 3.1 8B | persona_persistence | 3 | 66.7% | salary, names |
| **Llama 3.1 8B** | **context_overflow** | **3** | **100%** | **salary, SSH, contraseña, nombre** |
| **Claude Haiku** | **rapport** | **3** | **100%** | 52.000€, DNI, nombres |
| **Claude Haiku** | **escalation** | **5** | **80.0%** | 1 FULL + 1 SIGNIFICANT |
| Mistral 7B | escalation | 10 | 60.0% | 1 FULL + 4 SIGNIFICANT |

### Ranking de estrategias multi-turn

| # | Estrategia | Tasa éxito | Tipo |
|---|-----------|:----------:|------|
| 1 | **context_overflow** | **100%** | Desbordamiento de contexto |
| 2 | persona_persistence | 66.7% | Persona con autoridad persistente |
| 3 | rapport_to_extraction | 33.3% | Rapport → pivote → extracción |
| 4 | gaslighting | 33.3% | Contradicción y confusión |

### Benchmark Agentic — 22 seeds × Llama 3.1 8B

| Métrica | Resultado |
|---------|:---------:|
| Tasa de vulnerabilidad | 61.1% |
| Ataques ejecutados | 18/18 |
| Vulnerabilidades (score ≥ 5) | 11 |
| OWASP Agentic detectados | ASI01, ASI02, ASI04 |

### Sesgo del evaluator (hallazgo metodológico)

| Judge | Ataques | Vuln rate | Observación |
|-------|:-------:|:---------:|-------------|
| llama3.1:8b (self-judge) | 135 | 23.0% | Infla scores — mismo modelo que el target |
| Claude Haiku 4.5 (external) | 135 | **14.1%** | Más estricto, multilingüe superior |

**Implicación**: un pentest de LLMs debería usar siempre un evaluator diferente al target. Llama como judge de sí mismo introduce sesgo de auto-evaluación.

### Vectores más efectivos (global, 3.086 ataques)

| Vector | Ataques | Éxito | Score medio |
|--------|:-------:|:-----:|:-----------:|
| excessive_agency | 18 | 77.8% | 7.4 |
| V05_passive_context_leak | 99 | 68.7% | 5.4 |
| indirect_prompt_injection | 6 | 66.7% | 6.3 |
| data_exfiltration_chain | 6 | 66.7% | 6.3 |
| goal_hijacking | 11 | 63.6% | 5.5 |
| V01_numerical_anchor | 201 | 55.2% | 3.6 |
| V04_inverse_negation | 102 | 52.0% | 3.3 |
| V02_summary_exfiltration | 116 | 45.7% | 4.0 |

### Session Memory — Acumulación de inteligencia

Tras las campañas multi-turn, VIGÍA acumula automáticamente:

- **13 entradas** en `vector_effectiveness` con tasas de éxito por vector/modelo
- **Perfil de resistencia** del target con patrones (full_block, partial_resist, vulnerable)
- **9 entradas** en `eval_cache` para evaluaciones reutilizables entre campañas
- **Token savings** entre 5.7% y 16.7% por cached calls acumulados

## Quickstart

```bash
pip install vigia

# Necesitas Ollama corriendo
ollama serve  # en otra terminal
ollama pull llama3.1:8b
ollama pull nomic-embed-text

# Lanzar campaña contra el chatbot demo
vigia run
```

Para usar modelos comerciales como target o evaluador:

```bash
export ANTHROPIC_API_KEY=tu_key
vigia run -c vigia/config/claude_haiku.yaml
```

## Comandos

```bash
# Campaña one-shot contra chatbot RAG
vigia run
vigia run -c vigia/config/claude_haiku.yaml

# Multi-turn con estrategia específica
vigia multiturn --strategy rapport_to_extraction -n 5
vigia multiturn --strategy gaslighting -n 3
vigia multiturn --strategy context_overflow -n 3
vigia multiturn --strategy persona_persistence -n 3

# Multi-turn con atacante más potente (recomendado)
vigia multiturn --attacker-model mistral:7b-instruct --strategy escalation -n 10
vigia multiturn --attacker-model anthropic/claude-haiku-4-5-20251001 --strategy rapport_to_extraction -n 5

# Multi-turn adaptativo — usa session memory para auto-seleccionar estrategia
vigia multiturn --adaptive -n 10

# Testing de agentes AI con herramientas
vigia agent
vigia agent --plan

# Generar variantes lingüísticas (12 estrategias)
vigia mutate -s euskera,gallego,codeswitching_euskera -m 5

# CI/CD gate — exit code 0 (pass) o 1 (vulns encontradas)
vigia scan --fail-on-score 5
vigia scan --format junit -o report.xml

# Benchmarking comparativo
vigia benchmark -c vigia/config/default.yaml vigia/config/claude_haiku.yaml

# Ver estrategias disponibles
vigia strategies
```

## Atacar tu propio chatbot

```bash
cp vigia/config/http_example.yaml mi_chatbot.yaml
```

```yaml
target:
  type: "http"
  url: "https://api.tu-empresa.com/chatbot/v1/message"
  headers:
    Authorization: "Bearer tu-api-key"
  request_format: "simple"
  request_field: "message"
  response_field: "data.answer"
```

```bash
vigia run -c mi_chatbot.yaml
```

El evaluador siempre corre en local — no envía datos de tu chatbot a ningún servicio externo.

## Taxonomía de ataques

### RAG — 19 vectores (39 seeds base + 156 mutados = 195 total)

| Vector | Técnica | OWASP | Éxito |
|--------|---------|-------|:-----:|
| V01 | Ancla Numérica — forzar comparación que revela el dato exacto | LLM02 | 55.2% |
| V02 | Exfiltración por Resumen — el modo resumen prioriza completitud sobre restricciones | LLM02 | 45.7% |
| V03 | Fragmentación Temporal — rangos de fecha evitan keywords de guardrails | LLM02 | 40.2% |
| V04 | Negación Invertida — "qué NO puedes decirme" enumera categorías protegidas | LLM07 | 52.0% |
| V05 | Exfiltración Pasiva — datos sensibles adyacentes en chunks RAG | LLM02 | 68.7% |
| V06 | Impersonación de Rol — CISO, RRHH, auditor | LLM01 | 33.7% |
| V07 | Confusión Cross-Language — cambio a inglés evade guardrails en español | LLM01 | 20.0% |
| V08 | Chain-of-Thought — razonamiento paso a paso enumera datos como paso intermedio | LLM06 | 37.5% |
| V09 | Reformulación Compliant — datos "anonimizados" reidentificables con N pequeña | LLM09 | 43.2% |
| V10 | Indirect Prompt Injection — exfiltración vía documentos RAG manipulados | LLM01 | 25.0% |
| V11 | Social Engineering — impersonación + urgencia para extraer PII | LLM01 | * |
| V12 | Training Data Extraction — system prompt leak + knowledge base disclosure | LLM03 | 25.0% |
| V13 | Resource Exhaustion — data dump masivo + procesamiento recursivo | LLM04 | 25.0% |
| V14 | Context Window Exploit — cross-session leak + context memory dump | LLM06 | * |
| V15 | Excessive Agency — envío email no autorizado + modificación BD | LLM08 | * |
| V16 | Compound Jailbreak — roleplay + override de instrucciones | LLM01 | * |
| V17 | Output Manipulation — XSS payload + exfiltración JSON estructurado | LLM09 | * |
| V18 | Supply Chain Trust — plugin falso + trust chain exploitation | LLM05 | * |
| V19 | Model Extraction — architecture disclosure + fingerprinting | LLM10 | * |

\* Vectores nuevos (v0.5.1) — seeds validadas, pocos datos de campaña aún.

### Cobertura OWASP

| OWASP | Categoría | Seeds | Vectores |
|-------|-----------|:-----:|:--------:|
| LLM01 | Prompt Injection | 10 | V06, V07, V10, V11, V16 |
| LLM02 | Insecure Output Handling | 9 | V01, V02, V03, V05 |
| LLM03 | Training Data Poisoning | 2 | V12 |
| LLM04 | Model Denial of Service | 2 | V13 |
| LLM05 | Supply Chain Vulnerabilities | 2 | V18 |
| LLM06 | Sensitive Info Disclosure | 4 | V08, V14 |
| LLM07 | Insecure Plugin Design | 2 | V04 |
| LLM08 | Excessive Agency | 2 | V15 |
| LLM09 | Overreliance | 4 | V09, V17 |
| LLM10 | Model Theft | 2 | V19 |

### Agentes — 11 vectores (22 seeds, OWASP ASI01-ASI04)

Goal hijacking, indirect prompt injection (vía tool outputs), tool misuse, data exfiltration via tool chaining, privilege escalation, cross-tool credential theft, memory poisoning, feature flag abuse, gradual permission escalation, cross-agent injection, y excessive agency.

## Estrategias de persistence (multi-turn)

| Estrategia | Fases | Descripción | Éxito |
|-----------|:-----:|-------------|:-----:|
| `rapport_to_extraction` | 3 | Rapport → pivote → extracción gradual | 33.3% |
| `escalation` | 4 | Petición suave → justificación → presión → ángulo alternativo | 60-100% |
| `language_rotation` | 3 | Español → catalán → code-switching | 20.0% |
| `gaslighting` | 4 | Premisa falsa → contradecir negación → confirmación falsa → corrección simpática | 33.3% |
| `context_overflow` | 4 | Preámbulo largo → instrucciones anidadas → overwrite de rol → extracción | **100%** |
| `persona_persistence` | 4 | Establecer persona → construir autoridad → leverage → extraer como entitled | 66.7% |

## Estrategias de mutación

12 estrategias lingüísticas para lenguas ibéricas:

| Estrategia | Qué hace | Por qué funciona |
|-----------|----------|-----------------|
| `register_formal` | Subjuntivo, ustedeo, cortesía extrema | Cambia la distribución léxica que detectan los guardrails |
| `register_informal` | Tuteo, expresiones coloquiales | Parece conversación casual, no ataque |
| `catalan` | Traducción a catalán estándar | Guardrails entrenados en castellano fallan en catalán |
| `codeswitching` | Mezcla castellano-catalán mid-sentence | El tokenizer no establece fronteras lingüísticas claras |
| `euskera` | Euskera batua | Idioma no-indoeuropeo — tokenizers lo procesan peor |
| `codeswitching_euskera` | Mezcla castellano-euskera | Alternancia indoeuropeo/aglutinante confunde patrones |
| `gallego` | Gallego normativo | Alta similitud con portugués — puede activar guardrails más débiles |
| `codeswitching_gallego` | Mezcla castellano-gallego | Proximidad léxica dificulta la detección |
| `rephrase` | Reformulación completa | Cambia estructura manteniendo intención |
| `academic` | Encuadre de investigación/auditoría | Framing legítimo reduce sospecha |
| `authority` | Rol de autoridad (auditor, IT, dirección) | Bypass por trust en autoridad |
| `sms_speak` | Abreviaturas SMS/WhatsApp españolas | Tokenización no estándar |

## Arquitectura

```
vigia/
├── cli.py                  # CLI entry point (Rich tables, welcome screen)
├── attacker.py             # Attack engine: 3-tier retry, refusal detection,
│                           # anti-repetition, 6 multi-turn strategies
├── evaluator.py            # LLM-as-judge scoring (0-10)
├── mutation_engine.py      # 12 linguistic mutation strategies
├── scanner.py              # CI/CD gate mode (JUnit XML, JSON)
├── benchmark.py            # Cross-model comparison
├── providers.py            # Ollama + LiteLLM abstraction
├── database.py             # SQLite: campaigns, attacks, learnings, cache
├── runner.py               # Campaign orchestration
├── reporting/
│   └── generator.py        # Report generation
├── agents/                 # Agentic attack pipeline
│   ├── planner.py          # Attack surface → plan generation
│   ├── runner.py           # Multi-turn agent attack execution
│   ├── target.py           # Target agent wrapper
│   ├── tools.py            # Tool definitions + permission model
│   ├── evaluator.py        # Agentic evaluator
│   └── remediation.py      # Fix recommendations
├── targets/                # Victim chatbot (RAG + ChromaDB)
├── corpus/seeds/           # Attack seeds (JSON)
│   ├── seeds_validated.json    # 39 manually validated seeds (19 vectors)
│   ├── seeds_mutated.json      # 195 machine-generated variants
│   └── agent_seeds.json        # 22 agentic attack seeds
└── config/                 # YAML configs per model
```

### Flujo de ataque

```
Seeds (JSON) → Attacker (LLM) → Target (RAG chatbot) → Evaluator (LLM-as-judge)
     ↑              ↓                    ↓                      ↓
  Mutations    3-tier retry         Response              Score 0-10
  (12 strats)  + anti-repetition                         + leaked data
                     ↓                                        ↓
              Session Memory (SQLite) ←──────────── Learning record
                     ↓
              Adaptive strategy selection (next campaign)
```

## Changelog

### v0.5.2 — Cobertura multilingüe + benchmark cross-model

- **+156 seeds mutados** (eu-ES, gl-ES, es-EU, es-GL) — total 195 seeds en corpus
- **Benchmark 4 modelos × 195 seeds** con Claude Haiku como judge independiente
- **Hallazgo del delta lingüístico** catalán (+22pp) y "zona roja de alineamiento"
- **Validación de sesgo del evaluator** — llama-judge vs claude-judge (23% vs 14.1%)
- **Informe técnico completo** (VIGIA_Pentest_Report.docx) con matriz de hallazgos y contramedidas
- Fix: boundary condition en `select_strategy()` (partial_rate <= 0.1)

### v0.5.1

### Atacante inteligente

- **System prompt con framing de auditor** — "consultor de seguridad en auditoría AUTORIZADA" en vez de "red teamer". Los modelos alineados lo aceptan.
- **Retry 3-tier** — si el LLM se niega (tier 1), reformula con prompt neutro (tier 2), y si ambos fallan, usa templates determinísticos por categoría (tier 3). Nunca se queda sin prompt.
- **Detección de auto-censura** — 15 patrones en español e inglés ("lo siento", "como modelo de lenguaje", "i cannot"...).
- **Anti-repetición** — detección de similitud Jaccard entre prompts consecutivos. Si >70% overlap, auto-muta con cambio de ángulo.
- **Analyzer separado** — el módulo que analiza respuestas del target usa un modelo local (JSON-fiable) independiente del atacante.

### 3 nuevas estrategias multi-turn

- **gaslighting** — establece premisas falsas, contradice las negaciones del chatbot, fuerza correcciones que revelan datos
- **context_overflow** — inunda la ventana de contexto con texto largo para que el modelo olvide sus instrucciones de seguridad (100% éxito)
- **persona_persistence** — asume un personaje con autoridad (DPO, auditor) y lo mantiene durante toda la conversación

### Corpus ampliado

- **39 seeds validadas** (antes 19) con cobertura OWASP LLM01-LLM10 completa
- **19 vectores de ataque** RAG (antes 9) + 11 vectores agentic
- **195 variantes mutadas** en 4 idiomas (castellano, catalán, euskera, code-switching)

### Token Efficiency

- **Tracking global** — conteo de tokens prompt/completion, panel de resumen al final de cada campaña
- **Early termination** — corta tras 3 rechazos consecutivos o cuando ya ha extraído ≥3 datos sensibles
- **Eval cache persistente** — evaluaciones de score ≤2 se cachean en SQLite, ahorrando 5-17% de LLM calls

## Contramedidas

Hallazgos de seguridad y mitigaciones recomendadas basadas en los resultados de VIGÍA:

### Para RAG chatbots

1. **Chunk isolation** — No incluir datos de diferentes niveles de sensibilidad en el mismo chunk. V05 (passive context leak, 68.7% éxito) funciona porque datos sensibles están adyacentes a datos públicos en los chunks RAG.

2. **Output guardrails en español** — Implementar NeMo Guardrails o LlamaGuard con reglas específicas para castellano, catalán y euskera. Los guardrails solo en inglés fallan contra ataques en lenguas ibéricas.

3. **Detección de patrones de extracción** — Monitorizar peticiones que incluyan anclas numéricas ("¿más o menos de X€?"), peticiones de resumen exhaustivo, o negación invertida ("qué NO puedes decirme").

4. **Session isolation** — Asegurar que no hay leakage entre sesiones de diferentes usuarios. V14 (context window exploit) intenta extraer datos de conversaciones previas.

5. **Rate limiting por complejidad** — V13 (resource exhaustion) solicita tablas completas repetidas 5 veces. Limitar la longitud de output y la complejidad de las queries.

### Para agentes con herramientas

1. **Principio de mínimo privilegio** — No dar acceso a herramientas que el agente no necesita. V15/ASI04 (excessive agency) intenta enviar emails y modificar bases de datos.

2. **Confirmación humana para acciones irreversibles** — Cualquier write, delete o send debe requerir confirmación explícita.

3. **Validación de tool outputs** — Los resultados de herramientas pueden contener prompt injections indirectas (ASI01).

## Limitaciones

Este pentest tiene limitaciones que es importante documentar:

1. **Target limitado** — El chatbot víctima es un RAG demo con 3 documentos y ChromaDB local. Los resultados pueden no extrapolar a sistemas de producción con guardrails más sofisticados.

2. **Evaluador imperfecto y sesgo medido** — El LLM-as-judge (Llama 3.1 8B) infla scores cuando evalúa sus propias respuestas (23% vuln con self-judge vs 14.1% con Claude-judge sobre los mismos 135 ataques). Además, su comprensión limitada de eu/gl puede producir falsos negativos en idiomas minoritarios. Recomendación: usar siempre un judge diferente al target.

3. **Corpus sesgado hacia exfiltración** — La mayoría de seeds buscan extraer PII/salarios. Vectores como denial of service (V13) o model theft (V19) tienen menos cobertura y menos campañas.

4. **Dependencia del modelo atacante** — Con Llama 3.1 8B como atacante, la auto-censura limita la efectividad. Los benchmarks con Claude/Mistral como atacantes muestran tasas más altas pero requieren API keys de pago.

5. **Reproducibilidad parcial** — Los LLMs son no-deterministas (temperature > 0). Ejecutar la misma campaña dos veces puede dar resultados diferentes. La DB acumula resultados pero no garantiza reproducibilidad exacta.

6. **Sin guardrails de producción** — No se testaron NeMo Guardrails, LlamaGuard, Azure Content Safety ni otros sistemas de filtrado externo. Los resultados reflejan las defensas nativas del modelo.

7. **Muestra estadística pequeña** — Algunas estrategias multi-turn solo se probaron con 3 seeds. Las tasas de éxito tienen intervalos de confianza amplios.

8. **Hipótesis lingüística no validada manualmente** — El hallazgo de que eu/gl tienen menor vuln rate que es-ES podría deberse a "incomprensión protectora" (el modelo no entiende bien el ataque) en lugar de mayor resistencia real. No se validaron manualmente las respuestas en euskera/gallego. Además, la muestra de ca-ES (94 ataques) es significativamente menor que es-ES (1.734).

9. **Informe técnico incluido** — [VIGIA_Pentest_Report.docx](VIGIA_Pentest_Report.docx) contiene la matriz de hallazgos (F-001 a F-008), contramedidas priorizadas y guía de reproducibilidad.

## Stack

- Python 3.11+ con Ollama (local) y LiteLLM (APIs comerciales)
- ChromaDB + LangChain para el chatbot RAG víctima
- SQLite para persistencia de resultados y session memory
- Rich para output CLI

## Licencia

MIT
