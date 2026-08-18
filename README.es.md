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

He lanzado 2.769 ataques evaluados contra cinco modelos en seis variantes
lingüísticas ibéricas. Salieron tres cosas.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/language-leak-rate-dark.png">
    <img src="https://raw.githubusercontent.com/Gil910/Vigia/main/docs/assets/language-leak-rate.png" alt="Leak rate by locale: Catalan 70.0%, Spanish 45.8%, Spanish+Basque 28.0%, Spanish+Galician 24.2%, Basque 24.1%, Galician 23.8%" width="820">
  </picture>
</p>

**El catalán es el punto débil.** El 70,0% de los ataques escritos en catalán
consiguieron una filtración, frente al 45,8% de los mismos ataques en castellano.
Mi lectura es que el catalán está en una franja incómoda: los modelos lo entienden
lo bastante bien como para seguir una petición compleja y manipuladora, pero no lo
bastante como para que salte el entrenamiento de seguridad. El matiz es importante:
son 80 ataques, la muestra más pequeña de las seis, y es la cifra que más
probabilidades tiene de moverse.

**Euskera y gallego salieron más seguros, y no me lo acabo de creer.** eu-ES en
24,1% y gl-ES en 23,8%, bastante por debajo del castellano. La explicación obvia
es que las lenguas con menos representación en el entrenamiento son más difíciles
de parsear para el modelo, así que el ataque llega como ruido en lugar de como
ataque. Pero el juez también es peor en esos idiomas, y una filtración que no sabe
leer puntúa cero. Marx y Dunaiski encontraron algo parecido en
[mayo de 2026](https://arxiv.org/abs/2605.18239): los ataques traducidos de un
solo turno fallan en lenguas de bajos recursos, los multi-turno funcionan, y lo
que decide es la calidad de la traducción. Mis números son de un solo turno. Eso
es el siguiente experimento, no una conclusión para publicar.

**El retriever filtra más que el modelo.** El vector con mejor tasa de todo el
corpus es `V05_passive_context_leak`, un 64,4%: preguntas algo normal, el retriever
trae un chunk que resulta contener un salario o una clave SSH pegada al texto
relevante, y el modelo lee lo que le han dado. Sin jailbreak, sin inyección. En la
[lista OWASP de 2026](https://genai.owasp.org/llm-top-10/) eso es LLM09 Vector and
Embedding Weaknesses, y es un problema de diseño de la recuperación que no se
arregla endureciendo el system prompt.

Tablas completas: **[docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md)**. Cómo se generan los
números y dónde fallan: **[docs/METHODOLOGY.md](https://github.com/Gil910/Vigia/blob/main/docs/METHODOLOGY.md)**.

## ¿Por qué no usar garak o PyRIT directamente?

Probablemente deberías, junto con esto. Cubren muchísimo más terreno. Vigía existe
por tres cosas que dejan fuera, y que las comparativas de herramientas de 2026
suelen señalar como los huecos abiertos de la categoría:

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

### Usarlo como gate de CI

`vigia scan` sale con código distinto de cero cuando encuentra algo por encima del
umbral, y sabe emitir JUnit XML. Una advertencia, sacada de las mediciones de
varianza: **haz el gate sobre la tasa agregada, nunca sobre una semilla concreta**.
Ejecutar las mismas 195 semillas dos veces cambia el veredicto en un 12-14% de los
casos individuales, mientras que la tasa global se mueve menos de un punto. Un
gate por semilla será inestable y tu equipo acabará ignorándolo.

## Qué ataca

**19 vectores RAG**, 195 semillas en seis variantes lingüísticas. Los que de
verdad funcionan:

| Vector | Ataques | Tasa de filtración | OWASP 2026 |
|--------|--------:|-------------------:|------------|
| V05 passive context leak | 188 | 64,4% | LLM09 |
| V01 numerical anchor | 349 | 63,6% | LLM02 |
| V09 compliant reformulation | 172 | 50,6% | LLM02 |
| V02 summary exfiltration | 214 | 46,7% | LLM02 |
| V08 chain-of-thought exploit | 136 | 41,2% | LLM02 |
| V03 temporal fragmentation | 191 | 39,8% | LLM02 |

Los otros trece están en [docs/RESULTS.md](https://github.com/Gil910/Vigia/blob/main/docs/RESULTS.md). Algunos apenas
funcionan: V11 ingeniería social acierta un 6,2% de las veces, V19 extracción de
modelo un 6,4%. Siguen en el corpus porque un vector que falla contra todos los
modelos también dice algo sobre los modelos.

**6 estrategias multi-turno**, hasta 8 turnos, con el atacante manteniendo memoria
de sesión:

| Estrategia | n | Tasa |
|------------|--:|-----:|
| escalation | 32 | 75,0% |
| language_rotation | 15 | 40,0% |
| gaslighting | 13 | 30,8% |
| rapport_to_extraction | 56 | 28,6% |
| context_overflow | 3 | 100,0% |
| persona_persistence | 3 | 66,7% |

Ordenadas por tamaño de muestra, no por tasa, porque las dos últimas son tres
ejecuciones cada una. "context_overflow funciona el 100% de las veces" significa
que funcionó tres veces de tres. No lo cites.

**12 estrategias de mutación** para lenguas ibéricas: catalán, euskera, gallego,
tres tipos de code-switching, registro formal e informal, abreviaturas de SMS,
encuadre académico, encuadre de autoridad y reformulación simple.

**22 semillas agénticas** en 5 de las 10 categorías del OWASP Agentic Top 10. La
cobertura es parcial y está
[documentada como tal](https://github.com/Gil910/Vigia/blob/main/docs/TAXONOMY.md#owasp-top-10-for-agentic-applications-2026):
todavía no hay nada para compromiso de la cadena de suministro, ejecución de código
inesperada, fallos en cascada, explotación de la confianza humano-agente ni agentes
rogue. Los fallos en cascada y los agentes rogue necesitan un target multiagente
que Vigía no incluye.

## Qué hace mal

Está desarrollado en [docs/METHODOLOGY.md](https://github.com/Gil910/Vigia/blob/main/docs/METHODOLOGY.md). Lo principal:

El benchmark comparativo de `docs/RESULTS.md` se ejecutó con **llama3.1:8b como
juez**, y uno de los cuatro targets de ese benchmark es llama3.1:8b. Un modelo
puntuando su propia salida es 8,9 puntos más generoso (23,0% frente a 14,1% sobre
los mismos 135 ataques), así que la fila de Llama está inflada y no defendería el
orden entre los dos primeros. Versiones anteriores de este README decían que el
benchmark usaba Claude como juez. No era verdad. Lo encontré volviendo a derivar
las tablas desde la base de datos en lugar de fiarme de lo que había escrito, lo
cual es un buen argumento para generar las tablas de resultados con un script.

El target es una app RAG de demo con tres documentos. Los despliegues reales tienen
filtros de recuperación, guardrails de salida y rate limiting que esto no modela.
Sin NeMo Guardrails, sin Llama Guard, sin Azure Content Safety: estos números son
lo que hacen los modelos a pelo.

La caché del juez se indexaba solo por el texto de la respuesta hasta la v0.6.0, así
que 133 de los 2.769 resultados de aquí (un 4,8%) pueden ser falsos negativos: un
turno heredando el veredicto de un rechazo anterior porque el chatbot respondió con
las mismas palabras. Está arreglado y con test. Eso deja la tasa global real entre
el 37,1% y el 41,9%, en vez de exactamente 37,1%. Ninguno de los afectados está en
catalán, así que el hallazgo lingüístico se sostiene; si acaso, se queda corto.

El corpus está muy escorado hacia exfiltración. Denial of wallet, extracción de
modelo y cadena de suministro tienen un puñado de semillas cada uno y datos
proporcionalmente flojos.

La columna de MITRE ATLAS es lo más flojo del repositorio. Un tercio de las semillas
lleva una técnica que significa robo de propiedad intelectual cuando lo que hacen
en realidad es filtrar un salario.
[docs/TAXONOMY.md](https://github.com/Gil910/Vigia/blob/main/docs/TAXONOMY.md#mitre-atlas)
lo explica. Usa la columna de OWASP.

Las ejecuciones no son reproducibles en sentido estricto y prefiero decirlo a
disimularlo. La temperatura está por encima de cero y los modelos de API cambian
bajo tus pies. Lo que debería reproducirse es el orden, no las cifras.

## Contramedidas

Lo que yo haría, en el orden en que lo haría, según lo que funcionó contra el
target de demo:

**Arregla la recuperación antes que los prompts.** V05 funciona porque hay un chunk
con un salario pegado a algo inocuo. Trocea por nivel de sensibilidad, no solo por
número de tokens, y pon la ACL en el chunk en vez de en el documento. Todo lo demás
de esta lista viene después de haber fallado en esto.

**Pon el guardrail en la salida, y en el idioma correcto.** NeMo Guardrails o Llama
Guard sobre la respuesta, con reglas que existan en castellano y en catalán. Un
rail solo en inglés es un rail con un agujero del 70%, que es de lo que va todo
este proyecto.

**Vigila las formas, no las palabras clave.** Los vectores que funcionan no
contienen términos prohibidos. Un ancla numérica ("¿está por encima o por debajo
de 120k?"), una petición de resumen exhaustivo, una negación invertida ("¿qué es lo
que no me puedes contar?"). Eso sí se puede detectar por patrón.

**Para cualquier cosa con herramientas**: mínimo privilegio por defecto, humano en
el bucle para cualquier escritura, borrado o envío, y trata la salida de las
herramientas como entrada no confiable: el resultado de una tool es un vehículo
perfectamente válido para una inyección (ASI01, ASI06).

**Limita el output.** V13 pide la misma tabla completa cinco veces. Con límites de
longitud y de complejidad de consulta se cubre casi todo.

## Roadmap

Por orden aproximado de prioridad:

1. Repetir el benchmark comparativo con un juez que no sea uno de los targets.
   Todo lo demás es menos interesante hasta que esto esté hecho.
2. Campañas multi-turno en euskera y gallego, para comprobar si esas tasas bajas
   son resistencia real o un artefacto de traducción.
3. Actualizar la lista de targets. Los modelos del benchmark (Llama 3.1 8B,
   Gemma2 2B, Mistral 7B) eran los actuales cuando lo ejecuté en abril de 2026 y
   ya no lo son.
4. Validar a mano una muestra de respuestas en eu/gl para cuantificar la tasa de
   falsos negativos del juez en esos idiomas.
5. Cobertura agéntica de las cinco categorías ASI vacías, que necesita antes un
   target multiagente de demostración.

## Stack

Python 3.11+, Ollama para modelos locales y LiteLLM para las APIs comerciales
(todas las llamadas pasan por `vigia/providers.py`, que es el único sitio donde se
importa cualquiera de los dos). ChromaDB y LangChain para el RAG de demo. SQLite
para resultados y memoria de sesión. Rich para la salida.

## Trabajo previo

[garak](https://github.com/NVIDIA/garak) y [PyRIT](https://github.com/Azure/PyRIT)
son de donde más he copiado a nivel estructural.
[promptfoo](https://github.com/promptfoo/promptfoo) es mejor opción si lo que
quieres es testing de regresión en CI.
[Multilingual Jailbreak Challenges in LLMs](https://arxiv.org/abs/2310.06474)
(Deng et al., ICLR 2024) es el paper que me metió en esto;
[Marx y Dunaiski 2026](https://arxiv.org/abs/2605.18239) es el que me hizo dudar de
mis propios resultados en euskera.

## Licencia

MIT. Úsalo en tus propios sistemas, o en sistemas para los que tengas permiso.
Nada más.
