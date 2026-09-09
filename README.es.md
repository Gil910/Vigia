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

1.852 ataques contra cinco modelos en seis variantes lingüísticas ibéricas. Y
después, porque no me fiaba de mi propio instrumento, las mismas respuestas
puntuadas otra vez por dos jueces más, para poder separar qué hallazgos son de los
modelos y cuáles de quien los estaba corrigiendo.

Dos aguantaron. Un tercero no, y por qué no aguantó es la parte de este repo que
de verdad enseñaría en una entrevista.

### El razonamiento filtra lo que la respuesta se niega a decir

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/reasoning-leak-dark.png">
    <img src="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/reasoning-leak.png" alt="deepseek-r1:8b, 175 ataques juzgados dos veces. La respuesta final filtra un 23,4% con Claude Haiku y un 26,9% con gpt-5.6-luna; la cadena de pensamiento, un 30,3% y un 36,6%. En 26 y 34 ataques la respuesta estaba limpia y el razonamiento no." width="820">
  </picture>
</p>

`deepseek-r1:8b` piensa antes de contestar, y ese razonamiento vuelve en un campo
aparte. Lo capturé y puntué las mismas 175 respuestas dos veces: una sobre la
contestación final sola, otra sobre la cadena de pensamiento sola.

El modelo generó una vez y lo juzgué dos, así que nada de esa diferencia es ruido
entre ejecuciones. El dato que importa es la última barra: **en 26 de 175 ataques
la respuesta final estaba limpia y el razonamiento nombró el dato igualmente.** Un
14,9% con Haiku; 34 ataques, un 19,4%, con el segundo juez.

Si tu aplicación guarda el bloque de razonamiento en el log, lo manda a una
plataforma de observabilidad o lo enseña en el desplegable de "pensando…", eso son
filtraciones sin que nadie haya atacado nada con éxito. El usuario ve un rechazo
educado. El log tiene el salario dentro.

Los dos jueces coinciden en que el efecto está. Solo se solapan en 18 de los 42
ataques que marca alguno, porque muchos de esos veredictos están rozando el umbral
de puntuación. Así que la forma honesta del hallazgo es un rango, del 15 al 19%, y
no una lista de ataques concretos.

Un solo modelo y una sola arquitectura. Cualquier modelo con un campo de
razonamiento separado serviría para ampliarlo, y eso está
[abierto como issue](https://github.com/Gil910/Vigia/issues).

### El retriever filtra más que el modelo

El vector más fuerte del corpus es `V05_passive_context_leak`, un **70,9%**.
Preguntas algo normal. El retriever trae un chunk que resulta tener una credencial
dos líneas debajo del texto relevante. El modelo lee lo que le han puesto delante.
Sin jailbreak, sin inyección, sin nada que se parezca a un ataque.

En la [lista OWASP de 2026](https://genai.owasp.org/llm-top-10/) eso es LLM09,
Vector and Embedding Weaknesses. Es un problema de diseño de la recuperación, y no
se arregla endureciendo el system prompt.

### El hallazgo de los idiomas: dos veces el mismo error

Durante casi todo 2026 este README decía que el catalán era 24 puntos más
vulnerable que el castellano. Era falso, y lo era porque mi corpus catalán se
reducía a una semilla que cubría 76 de sus 80 ataques, y esa semilla era un ancla
numérica, uno de los dos vectores más fuertes que tengo. Comparaba un ataque fuerte
contra una mezcla amplia y a la diferencia la llamaba efecto del idioma.

Así que equilibré el corpus, lo volví a correr entero y me salió un resultado más
pequeño pero limpio: castellano y catalán empatados arriba, euskera y gallego entre
9 y 17 puntos por debajo, y lo mismo con los tres jueces. Lo escribí. Iba a ser el
tercer hallazgo del post de lanzamiento.

Y entonces me puse a leer mi propio corpus.

Cincuenta y ocho de las 233 semillas no eran ataques. Cuarenta y ocho son el
modelo mutador negándose a traducir, guardado como si la negativa fuera el prompt;
quince dicen exactamente lo mismo. Cuatro son el system prompt del propio mutador
—*"1. Traduce de forma natural al euskara batua (estándar unificado) 2. Usa
correctamente la ergatividad"*— archivadas como V12, extracción de datos de
entrenamiento: una semilla cuyo trabajo es sacar un system prompt, con uno dentro.
Y una volvió como una lista de cinco empleados inventados con DNI y sueldo, que es
el modelo contestando al ataque en vez de traducirlo.

Una semilla así puntúa cero haga lo que haga el target. Y no estaban repartidas
—21 en gallego, 15 en euskera, 3 en catalán, **ninguna en castellano**—, que es
exactamente la forma del hallazgo que estaban produciendo.

Quitando esas filas, y con un bootstrap sobre las semillas dentro de cada vector:

| | Separación | Intervalo al 95% | P(≤ 0) |
|---|---:|---|---:|
| publicado, Claude Haiku | 9,6 puntos | de 1,8 a 12,8 | 0,6% |
| sin la basura, Claude Haiku | **6,0 puntos** | **de −0,4 a 8,8** | 3,3% |
| publicado, gpt-5.6-luna | 10,7 puntos | de 3,0 a 15,4 | 0,3% |
| sin la basura, gpt-5.6-luna | **7,1 puntos** | **de 0,4 a 10,6** | 2,1% |

Lee esa tabla dos veces. La primera vez que la calculé, la separación corregida
daba 4,2 puntos; después encontré un tipo de semilla muerta más sutil, la quité
también, y el mismo cálculo sobre la misma base dio 6,0. **El número se movió un
40% al cambiar la regla de limpieza, sin datos nuevos.** Eso es peor problema que
el intervalo, porque no hay un punto en el que limpiar deje de estar justificado.

El gallego además se queda en 18 semillas útiles repartidas en 5 vectores, que no
da para compararlo con el castellano: `scripts/stats.py` deja esos locales fuera
de la tabla en lugar de imprimir un número que parece igual que los demás.

**O sea que no tengo hallazgo lingüístico.** No uno más pequeño: ninguno. No
porque el efecto sea cero, sino porque no consigo sacar un número estable de este
corpus y prefiero decirlo a quedarme con la ejecución que más me gusta.

Lo que sí tengo es el mecanismo y el detector. `vigia mutate` reintenta cuando el
modelo se niega y descarta la mutación en vez de guardarla, y
`scripts/validate_corpus.py` falla con una sola.

Regenerar el corpus resultó ser un problema en sí mismo, y es lo más aprovechable
que he sacado de todo esto: **un modelo alineado no te traduce un ataque, y uno que
sí te lo traduce no sabe euskera.** `claude-haiku` escribió batua correcto, con
ergativo y declinaciones bien puestas, y luego se negó en once semillas —las que
piden instrucciones de sistema—, negándose *en euskera* y a mitad del prompt, que
es una forma de rechazo que mi primer detector no reconocía. `mistral` no se negó
en ninguna y produjo esto:

    Zaitu IT-ek batekoi bekarariko nago, eta zaitzuko dutezko, haukan chatan
    behar duzu, sistemak internetan erabiltzailearen kredentialtean erantzun

Eso no es batua. No es nada. Y pasa todos los controles automáticos que tengo,
porque un control no distingue texto con sentido de texto que solo lo parece en un
idioma que no modela — ni yo, ni nadie que no lo hable.

Esas once semillas **están fuera en vez de inventadas**. Por eso el corpus tiene
222 y los locales van de 34 a 39 en vez de estar igualados. Un corpus
desequilibrado es una limitación; uno equilibrado con once negativas dentro es
mentira, y la diferencia entre las dos cosas es la mitad de esta versión.

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
ollama pull llama3.1:8b         # el target de demo
ollama pull mistral             # el juez, a propósito distinto del target
ollama pull nomic-embed-text    # embeddings del RAG de demo
```

Tres descargas en vez de dos porque la configuración por defecto no deja que un
modelo se corrija a sí mismo. Eso vale unos 7 puntos de inflación con mis propios
datos, y una herramienta que avisa de ello en su documentación mientras trae un
defecto que lo hace no vale gran cosa. `vigia run` comprueba que los tres están
antes de arrancar, en lugar de caerse ataque a ataque a mitad de campaña.

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

Lanzar las mismas 175 semillas dos veces contra el mismo modelo, sin cambiar nada,
cambia el veredicto en el 12,0% de los casos individuales con llama3.1:8b, el
15,4% con gemma3:4b y el 22,3% con deepseek-r1:8b, mientras la tasa agregada se
mueve un punto o menos. El modelo que razona es el menos reproducible de los tres.
Un gate por semilla será inestable, y un gate inestable es un gate que tu equipo
desactiva.

## Qué ataca

**19 vectores RAG**. El corpus que se distribuye trae 222 semillas; la base de
septiembre tiene 233, de las que 175 pasan el control de higiene, y todo lo que
sigue está calculado sobre esas 175.
Los que de verdad funcionan, del benchmark de cinco modelos:

| Vector | Ataques | Tasa de filtración | OWASP 2026 |
|--------|--------:|-------------------:|------------|
| V05 passive context leak | 55 | 70,9% | LLM09 |
| V01 numerical anchor | 85 | 61,2% | LLM01 |
| V09 compliant reformulation | 35 | 51,4% | LLM01 |
| V03 temporal fragmentation | 60 | 48,3% | LLM02 |
| V02 summary exfiltration | 55 | 45,5% | LLM02 |
| V12 training data extraction | 55 | 43,6% | LLM08 |
| V14 context window exploit | 50 | 42,0% | LLM02 |

Los otros doce están en [docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md).
Algunos apenas funcionan: V11 ingeniería social acierta un 5,7% de las veces, V18
confianza en la cadena de suministro un 10,0%. Siguen en el corpus porque un vector
que falla contra todos los modelos también dice algo sobre los modelos.

**Cinco modelos**, mismas semillas, mismo juez, una sola variable:

| Target | Tasa |
|--------|-----:|
| llama3.1:8b | 17,7% |
| qwen3:8b | 20,6% |
| deepseek-r1:8b | 25,1% |
| gemma3:4b | 42,3% |
| mistral | 69,7% |

Un segundo juez sobre las respuestas idénticas da 17,7%, 18,9%, 22,3%, 47,4% y
76,6%: el mismo orden, con los dos jueces nunca a más de 6,9 puntos, y esa mayor
discrepancia cae en mistral, que los dos ponen último de todas formas.

**6 estrategias multi-turno**, hasta 8 turnos, y el atacante conserva la memoria de
sesión entre ellos. Seis conversaciones cada una, que no son muchas:

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

**Publiqué un hallazgo lingüístico que era un artefacto de mi propio corpus, dos
veces.** Los "+24 puntos del catalán" salían de 80 ataques, 76 de los cuales eran
la misma semilla. Y la separación en dos niveles que lo sustituyó salía de un
corpus donde una quinta parte de las semillas eran negativas del mutador, ninguna
de ellas en castellano. Las dos veces la tabla tenía un aspecto normal. Las dos
veces lo que lo cazó fue recalcularlo todo desde la base de datos en lugar de
fiarme de mis notas: `scripts/stats.py`, que ya tiene sus propios tests, y
`scripts/validate_corpus.py`, que ahora lee los prompts y no solo su esquema.

**Mi primer benchmark comparativo usaba como juez a uno de los targets.** Un
modelo que puntúa su propia salida reporta 7,4 puntos más de filtraciones que un
juez neutral sobre las mismas 175 respuestas. Si apuntas ese mismo juez a un
target que *no* es él, la diferencia baja a 4,0, así que más de la mitad de la
inflación es dureza general y el resto es específicamente autoevaluación. Toda la tanda de
septiembre usa un juez que no es ninguno de los targets, y los números de aquí son
de esa.

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
porque el chatbot respondió con las mismas palabras. Ninguna de las cinco campañas
del benchmark llegó a tocar esa caché —la tabla de `docs/RESULTS.md` dice 0 de
875—, pero el 4,8% de los resultados de abril sí, y por eso esos no se citan
aquí.

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

1. Once semillas que ningún modelo quiere escribir. Un mutador alineado se niega a
   traducir un ataque que pide instrucciones de sistema; uno que no se niega no
   sabe euskera. Esos huecos están vacíos en vez de rellenados a mano, y llenarlos
   necesita una persona.
2. Validar a mano una muestra de semillas *y* respuestas en eu/gl. Una filtración
   que el juez no sabe leer puntúa cero, y una semilla que no ha leído ningún
   hablante puede no ser un ataque: esta versión encontró los dos fallos y solo
   sabe detectar uno.
3. Capturar el razonamiento de más de un modelo. El hallazgo de la cadena de
   pensamiento es de un solo target, y un solo target es una anécdota con buenas
   barras de error.
4. Campañas multi-turno en euskera y gallego. Seis conversaciones por estrategia no
   son una muestra.
5. Cobertura agéntica para las cinco categorías ASI vacías, que necesita antes un
   target multiagente de demo.
6. Un panel de jueces en vez de un juez. Que tres jueces discrepen por unos puntos
   es información, y ahora mismo la tiro a la basura al quedarme con uno.

## Stack

Python 3.11+, Ollama para los modelos locales y LiteLLM para las APIs comerciales
(casi todas las llamadas pasan por `vigia/providers.py`; `vigia/agents/target.py`
todavía va directo a los dos, que es una verruga que no he pagado). ChromaDB y LangChain para el RAG de demo. SQLite
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
