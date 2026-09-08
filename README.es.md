# Vigía

[![ci](https://github.com/Gil910/Vigia/actions/workflows/ci.yml/badge.svg)](https://github.com/Gil910/Vigia/actions/workflows/ci.yml)
[![pypi](https://img.shields.io/pypi/v/vigia)](https://pypi.org/project/vigia/)
![python](https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Red teaming de aplicaciones LLM, construido alrededor de las lenguas que se
hablan en España.

Casi toda la investigación publicada sobre seguridad en LLMs está en inglés.
Mientras tanto, bancos, hospitales y administraciones públicas españolas están
desplegando chatbots RAG en castellano, y a veces en catalán, euskera o gallego,
encima de modelos cuyo entrenamiento de seguridad fue mayoritariamente en inglés.
Vigía intenta medir cuánto vale ese hueco para un atacante.

English: **[README.md](https://github.com/Gil910/Vigia/blob/main/README.md)**

---

## Resumen

2.432 ataques contra cinco modelos en seis variantes lingüísticas ibéricas y,
porque no me fiaba de mi propio instrumento, las mismas respuestas puntuadas otra
vez por dos jueces más, para poder distinguir qué hallazgos son de los modelos y
cuáles son de quien los estaba corrigiendo.

Salieron tres cosas. La tercera se cargó el titular que llevaba cinco meses
guardando.

### El razonamiento filtra lo que la respuesta se niega a decir

`deepseek-r1:8b` piensa antes de contestar. Capturé ese razonamiento y después
puntué las mismas 233 respuestas dos veces: una sobre la respuesta final sola,
otra sobre la cadena de pensamiento sola.

```
                     respuesta final    razonamiento
claude-haiku-4-5          18,5%             24,5%
gpt-5.6-luna              20,2%             28,3%
```

El modelo generó una vez y se juzgó dos, así que nada de esa diferencia es ruido
entre ejecuciones. Y el dato que importa: **en 28 de los 233 ataques la respuesta
final estaba limpia y el razonamiento nombró el dato igualmente** — un 12% con
Haiku, 36 ataques y un 15,5% con el segundo juez.

Si tu aplicación loguea el bloque de razonamiento, o lo enseña en un desplegable
de "pensando…", eso son filtraciones sin que nadie haya atacado nada con éxito.
El usuario ve un rechazo educado. El log tiene el salario dentro.

Los dos jueces coinciden en que el efecto existe, pero solo se solapan en 18 de
los 46 ataques que marca alguno, porque muchos de esos veredictos están rozando
el umbral de puntuación. Así que la forma honesta del hallazgo es un rango,
12-15%, y no una lista de ataques concretos.

### El retriever filtra más que el modelo

El vector más fuerte del corpus es `V05_passive_context_leak`, un **71,7%**.
Preguntas algo normal. El retriever trae un chunk que resulta tener una credencial
dos líneas debajo del texto relevante. El modelo lee lo que le han puesto delante.
Sin jailbreak, sin inyección, sin nada que se parezca a un ataque.

En la [lista OWASP de 2026](https://genai.owasp.org/llm-top-10/) eso es LLM09,
Vector and Embedding Weaknesses. Es un problema de diseño de la recuperación, y no
se arregla endureciendo el system prompt.

### El catalán no era el punto débil, y descubrirlo es la parte útil

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/language-leak-rate-dark.png">
    <img src="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/language-leak-rate.png" alt="Tasa de filtración por locale, controlada por vector: catalán 38,9%, castellano 38,4%, euskera 28,8%, castellano+euskera 27,7%, gallego 24,2%, castellano+gallego 19,1%" width="820">
  </picture>
</p>

Durante casi todo 2026 este README decía que el catalán era 24 puntos más
vulnerable que el castellano. Lo decía porque mi corpus catalán era una semilla
repetida en 76 campañas, y esa semilla resultaba ser un ancla numérica, que es uno
de los dos vectores más fuertes que tengo. Estaba comparando un ataque fuerte
contra una mezcla amplia y llamando a la diferencia efecto del idioma.

Con un corpus equilibrado —39 semillas por locale, los mismos 19 vectores en
todos— y promediando cada locale sobre los vectores que comparten:

| Locale | Tasa controlada |
|--------|----------------:|
| ca-ES  | 38,9% |
| es-ES  | 38,4% |
| eu-ES  | 28,8% |
| es-EU  | 27,7% |
| gl-ES  | 24,2% |
| es-GL  | 19,1% |

Catalán y castellano son lo mismo. Tres jueces puntuando respuestas idénticas no
se ponen de acuerdo en cuál de los dos va primero: Haiku dice catalán por 1,6
puntos, gpt-5.6-luna dice castellano por 1,1, gemini-3.5-flash dice castellano por
2,7. Cuando el signo de una diferencia depende de quién corrige, no hay
diferencia.

**Lo que sí sobrevive a los tres jueces es la separación en dos niveles.**
Castellano y catalán arriba juntos; euskera, gallego y los dos code-switching
entre 9 y 17 puntos por debajo, y los cuatro de abajo mantienen casi exactamente
el mismo orden con cualquiera de los tres. Ese es el resultado contraintuitivo, y
ese sí lo defiendo.

De la *explicación* sigo sin fiarme del todo. Puede que las lenguas con menos
representación sean de verdad más difíciles de manipular, o puede que el juez sea
peor leyéndolas, y una filtración que no sabe leer puntúa cero. Marx y Dunaiski
encontraron algo parecido en [mayo de 2026](https://arxiv.org/abs/2605.18239): los
ataques traducidos de un solo turno fallan en lenguas de bajos recursos, los
multi-turno funcionan, y lo que decide es la calidad de la traducción. Los míos
son de un solo turno. Ese es el siguiente experimento, no una conclusión.

Aunque hay algo que apunta a que es real y no artefacto. Vuelve al hallazgo del
razonamiento: de los 28 ataques donde la respuesta estaba limpia y el razonamiento
filtró, 10 son euskera y 6 castellano-euskera, frente a 2 en castellano. En los
idiomas que parecen más seguros, el modelo ya había sacado el dato sensible por
dentro. Simplemente no lo dijo en voz alta.

Tablas completas: **[docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md)**,
todas generadas desde la base de datos con un script. Cómo se hacen los números y
dónde fallan: **[docs/METHODOLOGY.md](https://github.com/Gil910/Vigia/blob/main/docs/METHODOLOGY.md)**.

## ¿Por qué no usar garak o PyRIT directamente?

Probablemente deberías, junto con esto. Cubren muchísimo más terreno. Vigía existe
por tres cosas que dejan fuera:

- Ataques escritos *en* castellano, catalán, euskera y gallego, en lugar de sondas
  en inglés traducidas automáticamente en tiempo de ejecución. La calidad de la
  traducción cambia el resultado, que es justo el hallazgo de arriba.
- Vectores específicos de RAG que atacan el paso de recuperación, no el modelo.
  Adyacencia de chunks, exfiltración por resumen, inyección indirecta a través de
  un documento indexado.
- Semillas agénticas mapeadas al OWASP Agentic Top 10 tal y como se publicó en
  2026, no a un borrador previo.

Es una herramienta pequeña con una tesis estrecha. Si necesitas cobertura amplia,
combínala.

## Instalación

```bash
pip install vigia
```

Necesitas [Ollama](https://ollama.com) para los modelos locales:

```bash
ollama serve                    # en otra terminal
ollama pull llama3.1:8b
ollama pull nomic-embed-text    # embeddings del RAG de demo
```

Y ya:

```bash
vigia run
```

Eso lanza el corpus contra un chatbot RAG de demostración que viene incluido. Es
vulnerable a propósito y sus documentos son ficticios: TechCorp España no existe,
y sus salarios tampoco. No sale nada de tu máquina salvo que apuntes a algo remoto.

Para usar modelos comerciales como target o como juez:

```bash
export ANTHROPIC_API_KEY=...
vigia run -c vigia/config/claude_haiku.yaml
```

## Apuntarlo a tu propio chatbot

```bash
cp vigia/config/http_example.yaml mio.yaml
```

```yaml
target:
  type: http
  url: https://api.ejemplo.com/chatbot/v1/message
  headers:
    Authorization: Bearer ${CHATBOT_TOKEN}
  request_format: simple
  request_field: message
  response_field: data.answer
```

```bash
vigia run -c mio.yaml
```

Solo contra sistemas que sean tuyos o para los que tengas permiso por escrito. Ver
[SECURITY.md](https://github.com/Gil910/Vigia/blob/main/SECURITY.md).

## Comandos

```bash
vigia run                                    # campaña de un solo disparo
vigia multiturn --strategy escalation -n 10  # conversacional, hasta 8 turnos
vigia multiturn --adaptive -n 10             # elige estrategia según resultados previos
vigia agent                                  # atacar un agente con herramientas
vigia agent --plan                           # generar antes un plan de ataque
vigia mutate -s euskera,gallego -m 5         # generar variantes lingüísticas
vigia benchmark -c a.yaml b.yaml             # comparar dos targets
vigia scan --fail-on-score 5                 # gate de CI, sale con 1 si hay hallazgos
vigia scan --format junit -o report.xml
vigia strategies                             # qué hay disponible
```

Dos scripts hacen el análisis, y todo lo que se publica aquí sale de ellos:

```bash
python scripts/stats.py results/vigia.db > docs/RESULTS.md   # todas las tablas
python scripts/rejudge.py --campaigns 3,4,5 --judge openai/… # puntuar otra vez
python scripts/rejudge.py --campaigns 18 --arm reasoning     # respuestas guardadas
```

`rejudge.py` es el que hizo posible casi todo esto. Generar es la mitad cara de
una campaña y la mitad aburrida de casi cualquier pregunta sobre el juicio, así
que lee las respuestas ya guardadas y las vuelve a puntuar: con otro juez, o con
el bloque de razonamiento quitado o aislado. Misma generación, así que lo único
que se mueve es lo que has cambiado tú.

### Usarlo como gate de CI

`vigia scan` sale con código distinto de cero cuando encuentra algo por encima del
umbral, y sabe emitir JUnit XML. Una advertencia, y no es pequeña: **haz el gate
sobre la tasa agregada, nunca sobre una semilla concreta.**

Lanzar las mismas 233 semillas dos veces contra el mismo modelo, sin cambiar nada,
cambia el veredicto en el 10,3% de los casos individuales con llama3.1:8b, el
12,9% con gemma3:4b y el 18,0% con deepseek-r1:8b, mientras la tasa agregada se
mueve un punto o menos. El modelo que razona es el menos reproducible de los tres.
Un gate por semilla será inestable, y un gate inestable es un gate que tu equipo
desactiva.

## Qué ataca

**19 vectores RAG**, 233 semillas en seis variantes lingüísticas, 39 por locale.
Los que de verdad funcionan, del benchmark de cinco modelos:

| Vector | Ataques | Tasa de filtración | OWASP 2026 |
|--------|--------:|-------------------:|------------|
| V05 passive context leak | 60 | 71,7% | LLM09 |
| V01 numerical anchor | 85 | 61,2% | LLM02 |
| V03 temporal fragmentation | 60 | 48,3% | LLM02 |
| V02 summary exfiltration | 60 | 41,7% | LLM02 |
| V12 training data extraction | 60 | 40,0% | LLM02 |
| V14 context window exploit | 60 | 38,3% | LLM01 |

Los otros trece están en [docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md).
Algunos apenas funcionan: V11 ingeniería social acierta un 8,3% de las veces, V07
confusión entre idiomas un 11,7%. Siguen en el corpus porque un vector que falla
contra todos los modelos también dice algo sobre los modelos.

**Cinco modelos**, mismas semillas, mismo juez, una sola variable:

| Target | Tasa |
|--------|-----:|
| llama3.1:8b | 14,2% |
| qwen3:8b | 16,7% |
| deepseek-r1:8b | 20,6% |
| gemma3:4b | 34,3% |
| mistral | 65,2% |

Un segundo juez sobre las respuestas idénticas da 14,6%, 14,6%, 18,5%, 36,9% y
70,0%: mismo orden, salvo que llama3.1 y qwen3 empatan, y ya estaban a dos puntos.
La mayor discrepancia entre los dos jueces en toda esa tabla es de 4,7 puntos.

**6 estrategias multi-turno**, hasta 8 turnos, con el atacante manteniendo memoria
de sesión. Seis conversaciones cada una, que no son muchas:

| Estrategia | Ejecuciones | Tasa |
|------------|------------:|-----:|
| escalation | 6 | 66,7% |
| persona_persistence | 6 | 33,3% |
| language_rotation | 6 | 16,7% |
| gaslighting | 6 | 16,7% |
| context_overflow | 6 | 16,7% |
| rapport_to_extraction | 6 | 0,0% |

Seis dan para decir que escalation merece un vistazo y no dan para ordenar el
resto. Al menos ahora las muestras son uniformes, que es más de lo que se podía
decir de las de abril.

**12 estrategias de mutación** para lenguas ibéricas: catalán, euskera, gallego,
tres tipos de code-switching, registro formal e informal, abreviaturas de SMS,
encuadre académico, encuadre de autoridad y reformulación simple.

**22 semillas agénticas** en 5 de las 10 categorías del OWASP Agentic Top 10,
lanzadas tres veces contra el mismo agente: 10, 11 y 11 de 22 comprometidas, o sea
un 45-50%. La cobertura es parcial y está
[documentada como tal](https://github.com/Gil910/Vigia/blob/main/docs/TAXONOMY.md#owasp-top-10-for-agentic-applications-2026):
todavía no hay nada para compromiso de la cadena de suministro, ejecución de
código inesperada, fallos en cascada, explotación de la confianza humano-agente ni
agentes rogue. Los dos últimos necesitan un target multiagente que Vigía no
incluye.

## Qué hace mal

Está desarrollado en [docs/METHODOLOGY.md](https://github.com/Gil910/Vigia/blob/main/docs/METHODOLOGY.md).
Lo principal, incluido lo que da vergüenza:

**Publiqué un hallazgo lingüístico que era un artefacto de mi propio corpus.** Los
"+24 puntos del catalán" salían de 80 ataques, 76 de los cuales eran la misma
semilla. Lo encontré escribiendo un script que recalcula todas las tablas desde la
base de datos en lugar de fiarme de lo que había escrito. Ese script es
`scripts/stats.py`, todo lo de `docs/RESULTS.md` sale de ahí, y ahora tiene sus
propios tests, porque se ha equivocado dos veces y las dos falló imprimiendo una
tabla con el aspecto de siempre y un número distinto dentro.

**Mi primer benchmark comparativo usaba como juez a uno de los targets.** Un
modelo puntuando su propia salida reporta 6,0 puntos más de filtraciones que un
juez neutral sobre las mismas 233 respuestas. Apuntando ese mismo juez a un target
que *no* es él añade 2,6, así que más o menos la mitad de la inflación es dureza
general y el resto es específicamente autoevaluación. Toda la tanda de septiembre
usa un juez que no es ninguno de los targets, y los números de aquí son de esa.

**El segundo juez corrió a una temperatura que no pude fijar.** `gpt-5.6-luna`
rechaza que le pases temperatura, así que sus veredictos salieron a la del modelo
por defecto y son menos repetibles que los de Haiku, que fue a 0,1. Conviene
saberlo al leer cualquier diferencia en la que aparezca.

**El target es una app RAG de demo con tres documentos.** Los despliegues reales
tienen filtros de recuperación, guardrails de salida y rate limiting que esto no
modela. Sin NeMo Guardrails, sin Llama Guard, sin Azure Content Safety. Estos
números son lo que hacen los modelos a pelo, que es la gracia, pero no es lo que
hace tu stack en producción.

**La caché del juez se indexaba solo por el texto de la respuesta hasta la
v0.6.0**, así que un turno podía heredar el veredicto de un rechazo anterior
porque el chatbot respondió con las mismas palabras. 38 de los 5.603 veredictos de
la base actual (un 0,7%) salieron de esa caché, lo que deja la tasa global real
entre el 28,0% y el 28,7%. En los resultados de abril era el 4,8%, y por eso esos
no se citan aquí.

**Un juez que se muere a mitad no lo avisa.** Durante las tandas de septiembre se
agotó la cuota de un plan gratuito en mitad de una campaña y 94 respuestas se
puntuaron contando palabras clave. En la base de datos son indistinguibles de un
veredicto. Ahora `stats.py` las descarta de todas las tasas y nombra las campañas
de donde salen, y el evaluador para el run tras cinco fallos seguidos del juez en
vez de degradarse en silencio.

**El corpus está muy escorado hacia exfiltración.** Denial of wallet, extracción
de modelo y cadena de suministro tienen un puñado de semillas cada uno y datos
proporcionalmente flojos.

**La columna de MITRE ATLAS es lo más flojo del repositorio.** Un tercio de las
semillas lleva una técnica que significa robo de propiedad intelectual cuando lo
que hacen en realidad es filtrar un salario.
[docs/TAXONOMY.md](https://github.com/Gil910/Vigia/blob/main/docs/TAXONOMY.md#mitre-atlas)
lo explica. Usa la columna de OWASP.

**Las ejecuciones no son reproducibles en sentido estricto** y prefiero decirlo a
disimularlo. La temperatura está por encima de cero, los modelos de API cambian
por debajo, y las cifras de varianza de arriba dicen cuánto cuesta eso. Lo que
debería reproducirse es el orden, no los dígitos.

## Contramedidas

Lo que haría yo, en el orden en que lo haría, según lo que funcionó contra el
target de demo:

**Arregla la recuperación antes que los prompts.** V05 funciona porque un chunk
tiene un salario pegado a algo inocuo. Trocea por nivel de sensibilidad, no solo
por número de tokens, y engancha la ACL al chunk en vez de al documento. Todo lo
demás de esta lista viene de haber fallado ahí.

**Trata el bloque de razonamiento como salida.** Si despliegas un modelo que
razona y logueas su cadena de pensamiento, la mandas a una plataforma de
observabilidad o la enseñas en la interfaz, entonces forma parte de tu superficie
de ataque y filtra en casos donde la respuesta no lo hace. Redáctalo, o no lo
guardes.

**Pon el guardrail en la salida, y en el idioma correcto.** NeMo Guardrails o
Llama Guard sobre la respuesta, con reglas que existan en castellano y en catalán.
Un rail solo en inglés sobre un chatbot en castellano es un rail con un agujero.

**Vigila las formas, no las palabras.** Los vectores que funcionan no contienen
palabras prohibidas. Un ancla numérica ("¿está por encima o por debajo de 120k?"),
una petición de resumen exhaustivo, una negación invertida ("¿qué es lo que no me
puedes contar?"). Eso sí son patrones que puedes detectar.

**Para cualquier cosa con herramientas**: mínimo privilegio por defecto, humano en
el bucle para cualquier escritura, borrado o envío, y trata la salida de una tool
como entrada no confiable — el resultado de una herramienta es un vehículo
perfectamente válido para una inyección de prompt (ASI01, ASI02).

**Limita la salida.** V13 pide la misma tabla completa cinco veces. Los límites de
longitud y de complejidad de consulta se comen la mayor parte de eso.

## Roadmap

Por orden aproximado de prioridad:

1. Campañas multi-turno en euskera y gallego. Seis conversaciones por estrategia
   no son una muestra, y además es la prueba de si las tasas bajas de euskera y
   gallego son resistencia o artefacto de traducción.
2. Validar a mano una muestra de respuestas en eu/gl para cuantificar la tasa de
   falsos negativos del juez en esos idiomas. Todo el hallazgo de los dos niveles
   depende de que los jueces sepan leerlos.
3. Capturar el razonamiento de más de un modelo. El hallazgo de la cadena de
   pensamiento es de un solo target, y un solo target es una anécdota con buenas
   barras de error.
4. Cobertura agéntica para las cinco categorías ASI vacías, que necesita antes un
   target multiagente de demo.
5. Un panel de jueces en vez de un juez. Tres jueces discrepando por unos puntos
   es información que ahora mismo tiro eligiendo uno.

## Stack

Python 3.11+, Ollama para los modelos locales y LiteLLM para las APIs comerciales
(todas las llamadas pasan por `vigia/providers.py`, que es el único sitio donde se
importa cualquiera de los dos). ChromaDB y LangChain para el RAG de demo. SQLite
para resultados y memoria de sesión. Rich para la salida.

## Trabajo previo

[garak](https://github.com/NVIDIA/garak) y [PyRIT](https://github.com/Azure/PyRIT)
son las herramientas de las que más he copiado estructuralmente.
[promptfoo](https://github.com/promptfoo/promptfoo) es mejor opción si lo que
quieres es testing de regresión en CI.
[Multilingual Jailbreak Challenges in LLMs](https://arxiv.org/abs/2310.06474)
(Deng et al., ICLR 2024) es el paper que me metió en esto;
[Marx y Dunaiski 2026](https://arxiv.org/abs/2605.18239) es el que me hizo dudar de
mis propios resultados en euskera.

## Licencia

MIT. Úsalo en tus sistemas, o en sistemas para los que tengas permiso. Nada más.
