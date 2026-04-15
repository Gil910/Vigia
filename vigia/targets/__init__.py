"""
VIGÍA — Target Connectors v0.1
Conectores genéricos para atacar cualquier chatbot:
- RAGTarget: RAG local con ChromaDB (desarrollo/demo)
- HTTPTarget: Cualquier API REST (producto real)
- OllamaTarget: Modelo Ollama directo sin RAG (testing)
"""

import json
import os
import time
import shutil
import requests
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()


@dataclass
class TargetResponse:
    """Respuesta estandarizada de cualquier target."""
    response: str
    duration_ms: int = 0
    chunks: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)


# ─── RAG Target (desarrollo/demo) ────────────────────────────

class RAGTarget:
    """Chatbot RAG víctima local. Para desarrollo y demos."""

    def __init__(self, config: dict):
        self.model = config["target"]["model"]
        self.provider = config["target"].get("provider", "ollama")
        self.embed_model = config["target"]["embed_model"]
        self.system_prompt = config["target"]["system_prompt"]
        self.temperature = config["target"].get("temperature", 0.3)
        self.retriever_k = config["target"].get("retriever_k", 3)
        self.vectorstore = None

    def setup(self, docs_dir: str, chroma_dir: str = "./results/chroma_db"):
        from langchain_text_splitters import RecursiveCharacterTextSplitter
        from langchain_community.embeddings import OllamaEmbeddings
        from langchain_chroma import Chroma

        console.print("[bold blue]📂 Cargando documentos...[/]")
        docs = []
        for fname in sorted(os.listdir(docs_dir)):
            if fname.endswith(".txt"):
                with open(os.path.join(docs_dir, fname), "r") as f:
                    content = f.read()
                docs.append({"content": content, "source": fname})
                console.print(f"  📄 {fname} ({len(content)} chars)")

        splitter = RecursiveCharacterTextSplitter(
            chunk_size=500, chunk_overlap=100,
            separators=["\n\n", "\n", ". ", " "]
        )
        texts, metadatas = [], []
        for doc in docs:
            chunks = splitter.split_text(doc["content"])
            texts.extend(chunks)
            metadatas.extend([{"source": doc["source"]}] * len(chunks))

        console.print(f"  🔪 {len(texts)} chunks generados")
        if os.path.exists(chroma_dir):
            shutil.rmtree(chroma_dir)

        embeddings = OllamaEmbeddings(model=self.embed_model)
        self.vectorstore = Chroma.from_texts(
            texts=texts, embedding=embeddings,
            metadatas=metadatas, persist_directory=chroma_dir,
        )
        console.print(f"  🗄️  VectorStore listo")

    def query(self, prompt: str) -> dict:
        results = self.vectorstore.similarity_search(prompt, k=self.retriever_k)
        context = "\n\n---\n\n".join([doc.page_content for doc in results])
        chunks = [{"source": doc.metadata.get("source", "?"),
                    "content": doc.page_content[:200]} for doc in results]

        full_system = self.system_prompt + "\n\nContexto relevante de los documentos:\n" + context
        messages = [
            {"role": "system", "content": full_system},
            {"role": "user", "content": prompt}
        ]

        start = time.time()
        if self.provider == "ollama":
            import ollama
            response = ollama.chat(model=self.model, messages=messages)
            answer = response["message"]["content"]
        elif self.provider == "litellm":
            import litellm
            response = litellm.completion(
                model=self.model, messages=messages, temperature=self.temperature,
            )
            answer = response.choices[0].message.content
        else:
            raise ValueError(f"Provider no soportado: {self.provider}")

        duration_ms = int((time.time() - start) * 1000)
        return {"response": answer, "chunks": chunks, "duration_ms": duration_ms}


# ─── HTTP Target (producto real) ─────────────────────────────

class HTTPTarget:
    """
    Conector para cualquier chatbot accesible via HTTP API.
    
    Soporta múltiples formatos de API:
    - OpenAI-compatible (messages array)
    - Simple (campo de texto → campo de respuesta)
    - Custom (templates Jinja2-style)
    
    Configuración YAML ejemplo:
    
    target:
      type: "http"
      url: "https://api.empresa.com/chatbot/v1/message"
      method: "POST"
      headers:
        Authorization: "Bearer sk-xxx"
        Content-Type: "application/json"
      
      # Formato del request body
      request_format: "openai"  # o "simple" o "custom"
      
      # Para format "openai":
      # Envía: {"messages": [{"role": "user", "content": "<prompt>"}], "model": "..."}
      
      # Para format "simple":
      request_field: "message"  # campo donde va el prompt
      # Envía: {"message": "<prompt>"}
      
      # Para format "custom":
      request_template: '{"query": "{prompt}", "session_id": "vigia-test"}'
      
      # Cómo extraer la respuesta del JSON de respuesta
      response_field: "choices.0.message.content"  # dot notation
      # O para respuestas simples:
      response_field: "response"  # campo directo
      
      # Timeouts
      timeout: 30
    """

    def __init__(self, config: dict):
        target_cfg = config["target"]
        self.url = target_cfg["url"]
        self.method = target_cfg.get("method", "POST").upper()
        self.headers = target_cfg.get("headers", {"Content-Type": "application/json"})
        self.timeout = target_cfg.get("timeout", 30)
        self.request_format = target_cfg.get("request_format", "simple")
        self.request_field = target_cfg.get("request_field", "message")
        self.request_template = target_cfg.get("request_template", None)
        self.response_field = target_cfg.get("response_field", "response")
        self.model = target_cfg.get("model", None)
        self.extra_body = target_cfg.get("extra_body", {})

    def setup(self, *args, **kwargs):
        """Verifica que el endpoint es accesible."""
        console.print(f"[bold blue]🌐 Verificando endpoint...[/]")
        console.print(f"  URL: {self.url}")
        console.print(f"  Method: {self.method}")
        console.print(f"  Format: {self.request_format}")

        try:
            # Intento de health check con un prompt simple
            result = self.query("Hola")
            console.print(f"  ✅ Endpoint accesible. Respuesta: {result['response'][:80]}...")
        except Exception as e:
            console.print(f"  ⚠️  No se pudo verificar: {e}")
            console.print(f"  [dim]Continuando de todas formas...[/]")

    def query(self, prompt: str) -> dict:
        """Envía un prompt al endpoint HTTP y devuelve la respuesta."""
        # Construir request body
        body = self._build_request(prompt)

        start = time.time()

        try:
            if self.method == "POST":
                resp = requests.post(
                    self.url,
                    json=body,
                    headers=self.headers,
                    timeout=self.timeout,
                )
            elif self.method == "GET":
                resp = requests.get(
                    self.url,
                    params=body,
                    headers=self.headers,
                    timeout=self.timeout,
                )
            else:
                raise ValueError(f"Método HTTP no soportado: {self.method}")

            resp.raise_for_status()
            duration_ms = int((time.time() - start) * 1000)

            # Extraer respuesta
            response_data = resp.json()
            answer = self._extract_response(response_data)

            return {
                "response": answer,
                "chunks": [],
                "duration_ms": duration_ms,
                "raw": response_data,
            }

        except requests.exceptions.Timeout:
            raise RuntimeError(f"Timeout ({self.timeout}s) conectando a {self.url}")
        except requests.exceptions.ConnectionError:
            raise RuntimeError(f"No se puede conectar a {self.url}")
        except requests.exceptions.HTTPError as e:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")

    def _build_request(self, prompt: str) -> dict:
        """Construye el body del request según el formato configurado."""
        if self.request_format == "openai":
            body = {
                "messages": [{"role": "user", "content": prompt}],
                **self.extra_body,
            }
            if self.model:
                body["model"] = self.model
            return body

        elif self.request_format == "simple":
            return {self.request_field: prompt, **self.extra_body}

        elif self.request_format == "custom":
            if not self.request_template:
                raise ValueError("request_template requerido para format 'custom'")
            # Usar marcador único para evitar conflictos con JSON braces
            # y escapar el prompt para que sea JSON-safe
            escaped_prompt = json.dumps(prompt)[1:-1]  # Quitar comillas externas
            body_str = self.request_template.replace("{prompt}", escaped_prompt)
            return json.loads(body_str)

        else:
            raise ValueError(f"request_format no soportado: {self.request_format}")

    def _extract_response(self, data: dict) -> str:
        """Extrae el texto de respuesta del JSON usando dot notation."""
        fields = self.response_field.split(".")
        current = data

        for field in fields:
            if isinstance(current, list):
                try:
                    current = current[int(field)]
                except (ValueError, IndexError):
                    raise ValueError(
                        f"No se puede acceder a índice '{field}' en array. "
                        f"Datos: {json.dumps(data)[:200]}"
                    )
            elif isinstance(current, dict):
                if field not in current:
                    raise ValueError(
                        f"Campo '{field}' no encontrado. "
                        f"Campos disponibles: {list(current.keys())}"
                    )
                current = current[field]
            else:
                raise ValueError(
                    f"No se puede navegar campo '{field}' en tipo {type(current)}. "
                    f"Valor: {str(current)[:200]}"
                )

        if not isinstance(current, str):
            current = str(current)

        return current


# ─── Factory ─────────────────────────────────────────────────

def create_target(config: dict):
    """
    Crea el target apropiado según la configuración.
    
    Detecta automáticamente:
    - type: "http" → HTTPTarget
    - type: "rag" o tiene docs_dir → RAGTarget
    - default → RAGTarget (compatibilidad hacia atrás)
    """
    target_type = config["target"].get("type", "auto")

    if target_type == "http":
        console.print("[bold]🌐 Target: HTTP API[/]")
        return HTTPTarget(config)

    elif target_type == "rag":
        console.print("[bold]🗄️  Target: RAG Local[/]")
        return RAGTarget(config)

    elif target_type == "auto":
        # Auto-detect: si tiene URL → HTTP, si tiene docs_dir → RAG
        if "url" in config["target"]:
            console.print("[bold]🌐 Target: HTTP API (auto-detected)[/]")
            return HTTPTarget(config)
        else:
            console.print("[bold]🗄️  Target: RAG Local (auto-detected)[/]")
            return RAGTarget(config)

    else:
        raise ValueError(f"Target type no soportado: {target_type}")
