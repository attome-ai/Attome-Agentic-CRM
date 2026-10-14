# Local model servers

Attome's AI features use an OpenAI-compatible generation server and, for hybrid search, an
embedding server. Both can run on the same machine as Attome, so no prompt or document leaves it.
`deploy/model-servers/docker-compose.yml` has three optional profiles; none is needed to run Attome.

| Profile | What it serves | Address | Needs |
|---|---|---|---|
| `tei` | Embeddings (`BAAI/bge-m3`, Arabic and English) | `http://127.0.0.1:8088` | CPU |
| `llamacpp` | Generation from a GGUF model file | `http://127.0.0.1:8081/v1` | CPU; the `.gguf` in `deploy/model-servers/models` |
| `vllm` | Generation from a Hugging Face model | `http://127.0.0.1:8000/v1` | NVIDIA GPU |

```sh
docker compose -f deploy/model-servers/docker-compose.yml --profile tei up -d
MODEL_FILE=qwen2.5-7b-instruct-q4_k_m.gguf \
  docker compose -f deploy/model-servers/docker-compose.yml --profile llamacpp up -d
```

Then point Attome at them in `config.json` and restart it:

```json
"inference": {
  "ai": { "enabled": true, "fields": true, "chat": true, "semantic_search": true, "workflow_nodes": true },
  "generation": { "base_url": "http://127.0.0.1:8081/v1", "model": "qwen2.5-7b-instruct" },
  "embedding": { "base_url": "http://127.0.0.1:8088", "model": "BAAI/bge-m3" }
}
```

Before the first generation, add the model to the AI model catalogue (`ai_model`, with
`provider_model_id` equal to `generation.model`) and approve it: generation refuses a model that is
not approved. Give it an `input_cost` and `output_cost` per million tokens if money budgets
(`inference.spend`) should count it.

To run one task on another approved model (a small fast one for classification, a larger one
for answers), name it per action id; `agent.turn` covers chat and agent turns:

```json
"inference": { "task_models": { "record.classify": "<ai_model id>", "agent.turn": "<ai_model id>" } }
```

The model's provider must use the `openai-completions` protocol; its Base URL and key come from the
provider record.

An endpoint outside this machine or its private network is refused at boot unless
`inference.allow_external_provider` is true; an outside embedding endpoint is always refused.
Pin the images by digest for production.

## Reranking

The `rerank` profile serves a cross-encoder (`BAAI/bge-reranker-v2-m3`) through text-embeddings-
inference on `127.0.0.1:8089`. Set `inference.rerank.base_url` to `http://127.0.0.1:8089` and
`inference.rerank.model` to the model id. With an embedding model configured, knowledge retrieval
fuses the keyword and vector results; with a reranker too, the top 50 passages are reordered by
the reranker's score. A reranker that fails leaves the fused order and counts
`attome_search_leg_degraded_total{leg="knowledge_rerank"}`.

## Speech to text

The `speech` profile starts a faster-whisper server on `127.0.0.1:8090`. Set
`inference.speech.base_url` to `http://127.0.0.1:8090/v1` and `inference.speech.model` to the
model id. Recordings are customer data: the speech server must be inside the deployment whatever
`allow_external_provider` says. One upload is at most 25 MiB; the answer carries the text, the
language and timed segments.

## Reading text from images

The `ocr` profile serves a vision-language model (Qwen2.5-VL by default) on `127.0.0.1:8091`. Set
`inference.ocr.base_url` to `http://127.0.0.1:8091/v1` and `inference.ocr.model` to the model id.
PNG, JPEG and WebP images up to 10 MiB are read; the model is told to transcribe the text exactly,
Arabic as Arabic. Like speech, it must be inside the deployment.

## Model packs

`deploy/model-servers/ai-packs.json` lists the local model profiles (`cpu`, `gpu`): each model's
role, server address, licence, the tasks it was tested on and its weight files with SHA-256 and
size. `attome init --ai <profile> --ai-dir <dir>` (or with `--from-bundle <dir>`) checks every
weight file in the directory against the manifest, turns AI on in the written configuration with
generation and embeddings pointed at the profile's servers, and prints the `docker compose`
command that starts them. It never downloads weights. A profile is installable only once it is
approved, which needs every file's checksum and size from weights that were downloaded, tested and
scored; until then `init` lists it and refuses.
