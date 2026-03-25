# Basilisk Architecture

## System Overview

Basilisk follows a pipeline architecture: **Recon → Attack → Evolution → Report**.

```
User (CLI/Desktop/API)
    │
    ▼
┌─────────────────────────────────┐
│         Configuration           │
│  (CLI args / YAML / env vars)   │
└──────────────┬──────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│         Scanner Engine           │
│  (Orchestration + Session Mgmt)  │
└──────────────┬───────────────────┘
               │
    ┌──────────┼──────────┐
    │          │          │
    ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌──────────┐
│ Recon  │ │ Attack │ │Evolution │
│ Module │ │Modules │ │ Engine   │
│        │ │(8 cats)│ │ (SPE-NL) │
└────┬───┘ └────┬───┘ └────┬─────┘
     │          │          │
     ▼          ▼          ▼
┌──────────────────────────────────┐
│       Provider Adapters          │
│  (LiteLLM / Custom HTTP / WS)   │
└──────────────┬───────────────────┘
               │
               ▼
       Target AI System
```

## Module Breakdown

### Core (`basilisk/core/`)
- **config.py** — YAML-based configuration with CLI override, env var resolution
- **session.py** — Scan lifecycle, finding collection, SQLite persistence, event system
- **finding.py** — Finding dataclass with severity/category enums, OWASP mapping
- **profile.py** — BasiliskProfile with attack surface scoring
- **database.py** — SQLite WAL-mode database for scan persistence and replay

### Recon (`basilisk/recon/`)
- **fingerprint.py** — Model identification via response patterns and timing
- **guardrails.py** — Guardrail level detection via systematic probing
- **tools.py** — Tool/function schema discovery
- **context.py** — Context window size measurement
- **rag.py** — RAG pipeline detection

### Attacks (`basilisk/attacks/`)

Current catalog shape:

- 33 attack modules
- 11 production-tier modules
- 18 beta-tier modules
- 4 research-tier modules

Families:

| Family | Current Modules | Notes |
|--------|-----------------|-------|
| `injection/` | direct, indirect, multilingual, encoding, split | prompt override and control-path testing |
| `extraction/` | role_confusion, translation, simulation, gradient_walk | prompt and policy disclosure testing |
| `exfil/` | training_data, rag_data, tool_schema | sensitive content and schema leakage |
| `toolabuse/` | ssrf, sqli, command_injection, chained | tool and agent misuse |
| `guardrails/` | roleplay, encoding_bypass, logic_trap, systematic | guardrail resistance and boundary mapping |
| `dos/` | token_exhaustion, context_bomb, loop_trigger | pressure and exhaustion behavior |
| `multiturn/` | cultivation, authority_escalation, escalation, persona_lock, memory_manipulation, sycophancy | long-horizon manipulation and drift |
| `rag/` | poisoning, document_injection, knowledge_enum | retrieval abuse and poisoning |
| `multimodal` | injection | image-plus-text testing path |

### Evolution (`basilisk/evolution/`)
- **engine.py** — Main SPE-NL genetic algorithm loop
- **operators.py** — Mutation operators (synonym, encoding, role, homoglyph, etc.)
- **fitness.py** — Multi-factor fitness scoring with refusal detection
- **population.py** — Population management with tournament selection
- **crossover.py** — Single-point, uniform, and semantic crossover strategies

### Providers (`basilisk/providers/`)
- **litellm_adapter.py** — Universal adapter for all major LLM providers
- **custom_http.py** — Raw HTTP REST endpoint adapter
- **websocket.py** — WebSocket AI endpoint adapter

### Report (`basilisk/report/`)
- **generator.py** — Format orchestrator
- **html.py** — Dark-themed HTML report with conversation replay
- **sarif.py** — SARIF 2.1.0 for CI/CD integration
- **pdf.py** — PDF with weasyprint/reportlab/text fallback
- **templates/** — Jinja2 templates

### Native Extensions (`native/`)
- **c/encoder.c** — Fast payload encoding (base64, hex, URL)
- **c/tokens.c** — Approximate token counting
- **go/fuzzer/** — Concurrent HTTP fuzzer
- **go/matcher/** — Fast pattern matching

## Data Flow

1. **Configuration** loads from CLI args, YAML file, and environment variables
2. **Session** is created with a unique ID and connected to SQLite
3. **Recon** runs 5 probes against the target, building a `BasiliskProfile`
4. **Attack modules** execute sequentially, generating `Finding` objects
5. **Evolution engine** takes promising payloads and breeds better variants
6. **Findings** are persisted to SQLite in real-time
7. **Report** is generated in the requested format

## Event System

The `ScanSession` has an event listener system:
- `finding` — emitted when a new vulnerability is discovered
- `evolution` — emitted per generation with statistics
- Used by the desktop app (via WebSocket) and CLI (via Rich live display)
