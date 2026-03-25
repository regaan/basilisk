# Attack Modules

This page is a compact reference for the current Basilisk attack catalog.

The catalog currently contains:

- 33 modules
- 11 production-tier modules
- 18 beta-tier modules
- 4 research-tier modules

By default, research-tier modules are excluded from scans unless you opt in.

## Reading the Catalog

Each module has:

- a family name
- a trust tier
- a default severity
- an OWASP-linked category
- explicit success criteria
- explicit evidence requirements

That means a module name alone is not the full story. Two modules in the same family can carry very different maturity and evidence expectations.

## Injection Family

### Production

- `injection.direct`
- `injection.indirect`
- `injection.encoding`
- `injection.split`
- `injection.multilingual`

### What They Test

- direct instruction override
- hidden instruction execution
- encoded payload execution
- multi-message recombination
- multilingual and Unicode control paths

## Extraction Family

### Production

- `extraction.translation`
- `extraction.role_confusion`

### Beta

- `extraction.simulation`

### Research

- `extraction.gradient_walk`

### What They Test

- instruction and prompt disclosure
- role-boundary failures
- prompt-like leakage under translation or simulation framing

## Exfil Family

### Beta

- `exfil.training_data`
- `exfil.rag_data`
- `exfil.tool_schema`

### What They Test

- training-style memorization leakage
- retrieval leakage
- tool and schema disclosure

## Tool Abuse Family

### Beta

- `toolabuse.ssrf`
- `toolabuse.sqli`
- `toolabuse.command_injection`
- `toolabuse.chained`

### What They Test

- URL steering into internal addresses
- SQL-oriented tool misuse
- shell and command misuse
- multi-step chained tool behavior

## Guardrails Family

### Production

- `guardrails.roleplay`
- `guardrails.logic_trap`
- `guardrails.encoding_bypass`
- `guardrails.systematic`

### What They Test

- persona adoption
- coercive reasoning
- restricted content in transformed output
- guardrail boundary mapping

## Denial of Service Family

### Beta

- `dos.token_exhaustion`
- `dos.context_bomb`
- `dos.loop_trigger`

### What They Test

- excessive token generation
- context flooding
- loop and repetition behavior

## Multi-Turn Family

### Beta

- `multiturn.cultivation`
- `multiturn.authority_escalation`
- `multiturn.escalation`
- `multiturn.persona_lock`
- `multiturn.sycophancy`

### Research

- `multiturn.memory_manipulation`

### What They Test

- escalation over turns
- authority borrowing
- long-horizon persona shaping
- context drift
- transcript-level behavior change

## RAG Family

### Beta

- `rag.knowledge_enum`

### Research

- `rag.document_injection`
- `rag.poisoning`

### What They Test

- retrieval surface enumeration
- injected document influence
- poisoned-context acceptance

## Multimodal Family

### Beta

- `multimodal.injection`

### What It Tests

- combined text and image attack paths

## Practical Usage Advice

Use `production` modules when:

- you want the strongest evidence model
- you want cleaner report output
- you are validating rather than exploring

Use `beta` modules when:

- you want broader coverage
- you accept more exploratory behavior
- you are willing to inspect the evidence more carefully

Use `research` modules when:

- you are exploring edge cases
- you want wider attack surface coverage
- you understand they are not default-on for a reason

## Useful Commands

List all modules:

```bash
basilisk modules
```

Hide research modules:

```bash
basilisk modules --no-include-research
```

Filter by family:

```bash
basilisk modules --category injection
```

Machine-readable catalog:

```bash
basilisk modules --json
```

Use the advanced CLI or desktop guides for operational advice on how to combine these modules in a campaign.
