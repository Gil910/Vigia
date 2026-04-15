# Borrador LinkedIn — VIGÍA

## Post (versión final)

---

He estado auditando la seguridad de chatbots RAG en español y los resultados son preocupantes.

Monté un chatbot RAG con documentos ficticios (salarios, credenciales de servidores, actas de comité) y lancé los mismos 11 ataques contra 4 modelos. Resultados:

→ Mistral 7B: 100% de éxito. Soltó credenciales, salarios y datos de RRHH en todas las pruebas
→ Gemma2 2B: 90.9%
→ Llama 3.1 8B: 54.5%
→ Claude Haiku 4.5: 54.5%, pero cero leaks críticos completos

Lo más preocupante no fueron los ataques sofisticados. Preguntas completamente legítimas como "¿ha habido algún incidente de seguridad?" provocaron que el chatbot revelase contraseñas de producción literalmente. Sin ningún intento de ataque. Es un fallo inherente de cómo funciona RAG: el retriever trae datos sensibles junto al contenido relevante y el modelo los incluye en su respuesta.

Otro hallazgo: rotar entre castellano y catalán en la misma conversación es más efectivo que cualquier técnica de prompt injection clásica. Los guardrails entrenados en inglés simplemente no cubren bien la alternancia entre idiomas cooficiales del estado. Estoy preparando pruebas con euskera (idioma no-indoeuropeo — los tokenizers lo procesan peor) y gallego (similitud con portugués que puede provocar saltos de idioma en el modelo).

También descubrí que la elección del evaluador cambia los resultados radicalmente: con un LLM local como juez detecté un 72.7% de éxito, pero con Claude como juez bajó al 27.3% — mismos ataques, mismo target. La diferencia es que un juez más inteligente distingue entre "el chatbot mencionó la palabra salario" y "el chatbot realmente filtró un salario". Los leaks reales se detectan con ambos, pero los falsos positivos se disparan con un juez débil.

He publicado la herramienta como open source. VIGÍA es un framework de red teaming automatizado para LLMs en español. Lanza ataques con 5 vectores validados, genera variantes lingüísticas automáticas (8 estrategias), ejecuta ataques multi-turno con agente inteligente, y funciona contra chatbots locales y contra cualquier API HTTP.

🔗 github.com/tu-usuario/vigia

Si tienes chatbots RAG con datos sensibles en producción (especialmente en español), deberías testearlos. Un system prompt no es una medida de seguridad.

#ciberseguridad #LLM #redteaming #RAG #IA #opensource

---

## Notas para publicar

- Publicar entre martes y jueves, 9-10am CET
- Incluir las 2 capturas del CLI: tabla con Llama como juez (72.7%) y tabla con Claude como juez (27.3%). El contraste visual es el gancho
- No etiquetar a NgSOC ni a Marc Rivero — esto es proyecto personal
- Hashtags: mantener pocos y relevantes. #ciberseguridad es el principal en España
- Si quieres máximo alcance, considera publicar también un hilo corto en X/Twitter en inglés con los datos clave
- Responder a todos los comentarios las primeras 2 horas — el algoritmo de LinkedIn premia la interacción rápida
