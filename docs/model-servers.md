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

An endpoint outside this machine or its private network is refused at boot unless
`inference.allow_external_provider` is true; an outside embedding endpoint is always refused.
Pin the images by digest for production.
