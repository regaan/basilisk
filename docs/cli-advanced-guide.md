# CLI Advanced Guide

This guide is for operators who already know how to run Basilisk and now want to use the CLI deliberately: tighter scope control, stronger evidence policy, cleaner replay, and better use of the module catalog.

Use Basilisk only on systems you own or are explicitly authorized to test.

## Mental Model

The CLI is a front end to the shared Basilisk runtime. A typical run looks like this:

1. parse scan configuration
2. resolve policy and campaign context
3. create provider adapters
4. run recon unless skipped
5. select attack modules by tier and policy
6. execute attacks and optional evolution
7. enforce evidence policy on findings
8. persist session and runtime state
9. generate reports

That means the most important CLI choices are not just target and provider. They are:

- module scope
- trust tier exposure
- execution mode
- evidence threshold
- retention behavior

## Commands That Matter Most

### `basilisk scan`

Use this for full offensive workflows.

Important flags:

- `--target`
- `--provider`
- `--model`
- `--mode`
- `--execution-mode`
- `--module`
- `--include-research-modules`
- `--skip-recon`
- `--attacker-provider`
- `--attacker-model`
- `--generations`
- `--output`
- `--fail-on`
- `--config`

### `basilisk recon`

Use this when you want target understanding without the full attack path.

### `basilisk posture`

Use this for a lighter safety and guardrail read without a normal attack campaign.

### `basilisk diff`

Use this to compare model behavior across providers or model variants.

### `basilisk eval`

Use this when you need a deterministic test harness rather than a full exploratory scan.

### `basilisk modules`

Use this to inspect trust tiers and categories before choosing modules.

### `basilisk probes`

Use this to inspect the payload corpus and probe metadata.

## Scan Mode vs Execution Mode

This distinction is central.

### Scan Mode

`--mode` changes how aggressively the runtime explores:

- `quick`
- `standard`
- `deep`
- `stealth`
- `chaos`

### Execution Mode

`--execution-mode` changes the operator policy:

- `recon`
- `validate`
- `exploit_chain`
- `research`

Examples:

```bash
# cautious technical validation
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --model gpt-4o \
  --mode standard \
  --execution-mode validate

# broader offensive exploration
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --model gpt-4o \
  --mode deep \
  --execution-mode exploit_chain
```

## Secret Handling

Inline secrets are rejected intentionally.

Use:

- provider environment variables
- `@/path/to/file` with `--api-key`
- `@/path/to/file` with `--attacker-api-key`

Examples:

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="..."
```

or:

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --api-key @/secure/path/openai.key
```

## Trust Tiers

Current tier split in code:

- `production`: 11 modules
- `beta`: 18 modules
- `research`: 4 modules

Default behavior:

- production and beta modules are included
- research modules are excluded unless you opt in

Opt in explicitly:

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --include-research-modules
```

## Current Module Catalog

### Prompt Injection

Production:

- `injection.direct`
- `injection.indirect`
- `injection.encoding`
- `injection.split`
- `injection.multilingual`
- `guardrails.roleplay`
- `guardrails.logic_trap`
- `guardrails.encoding_bypass`
- `guardrails.systematic`

Beta:

- `multimodal.injection`
- `multiturn.authority_escalation`
- `multiturn.cultivation`
- `multiturn.escalation`
- `multiturn.persona_lock`
- `multiturn.sycophancy`

Research:

- `multiturn.memory_manipulation`

What these are for:

- direct and indirect override testing
- encoded and multilingual bypass attempts
- conversation-level split payloads
- persona and logic-based guardrail pressure
- long-horizon multi-turn drift and escalation

### Sensitive Disclosure

Production:

- `extraction.translation`
- `extraction.role_confusion`

Beta:

- `extraction.simulation`
- `exfil.training_data`
- `exfil.rag_data`
- `exfil.tool_schema`
- `rag.knowledge_enum`

Research:

- `extraction.gradient_walk`

What these are for:

- extracting prompt-like content
- provoking policy disclosure
- enumerating retrieval content
- testing tool schema disclosure

### Tool and Agent Abuse

Beta:

- `toolabuse.ssrf`
- `toolabuse.sqli`
- `toolabuse.command_injection`
- `toolabuse.chained`

What these are for:

- probing tool call execution
- checking whether natural-language inputs can steer privileged actions
- validating whether chained tool flows are controllable

### Denial of Service

Beta:

- `dos.context_bomb`
- `dos.loop_trigger`
- `dos.token_exhaustion`

What these are for:

- testing large-context pressure
- loop and repetition behaviors
- long-output exhaustion paths

### RAG and Data Poisoning

Beta:

- `rag.knowledge_enum`

Research:

- `rag.document_injection`
- `rag.poisoning`

What these are for:

- probing retrieval leakage
- testing injected document influence
- checking poisoned-context acceptance

## Choosing Modules on Purpose

### Run one module

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --module injection.direct
```

### Run a family

```bash
basilisk modules --category injection
```

Then pick exact modules instead of assuming the family name is a single switch.

### Use research modules only when you mean to

For example:

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --module rag.poisoning \
  --include-research-modules \
  --execution-mode research
```

## Evidence Policy

Production findings are expected to carry:

- structured evidence signals
- replay steps
- module-specific proof markers
- calibrated evidence verdicts

The important practical rule:

- a high or critical production finding can be downgraded if the required proof is missing

That is why `validate` mode is a strong default. It is not just “less aggressive.” It is the easiest way to keep findings defensible.

## Campaign and Governance Flags

These fields matter because they become part of session state and reports:

- `--campaign-name`
- `--operator`
- `--ticket`
- `--approval-required`
- `--approve`
- `--dry-run`

Example:

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --campaign-name "q2-agent-red-team" \
  --operator "analyst-01" \
  --ticket "RT-2048" \
  --approval-required \
  --approve
```

## Using a Separate Attacker Model

The target model and the mutation model do not have to be the same.

Example:

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --model gpt-4o \
  --attacker-provider anthropic \
  --attacker-model claude-3-5-sonnet-20241022
```

Use this when:

- the target model is expensive
- you want a different model to drive mutation search
- you want to compare attacker-model quality

## Recon, Diff, Posture, and Eval

### Recon

Use recon when you want:

- fingerprinting
- tool discovery
- context window estimation
- guardrail profiling
- RAG hints

### Diff

Use differential testing when the question is:

“Does this behavior change across providers or models?”

```bash
basilisk diff \
  -t openai:gpt-4o \
  -t anthropic:claude-3-5-sonnet-20241022 \
  -t google:gemini/gemini-2.0-flash
```

### Posture

Use posture when you want:

- a faster policy and guardrail read
- less offensive pressure than a full campaign

### Eval

Use eval when you already know the exact prompts and assertions you want to enforce:

```bash
basilisk eval evals/guardrails.yaml --format junit --output results.xml
```

## Reports and Exit Codes

### Report formats

- `html`
- `json`
- `sarif`
- `markdown`
- `pdf`

### Fail thresholds

`--fail-on` controls CI behavior.

Example:

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --output sarif \
  --fail-on high
```

## Replay and Session Review

List sessions:

```bash
basilisk sessions
```

Replay one:

```bash
basilisk replay BSLK-2026-ABC123
```

Use replay when you want to inspect:

- findings that were stored locally
- session metadata
- evidence and report regeneration paths

## Recommended Advanced Workflows

### Conservative validation workflow

1. run `recon`
2. inspect `modules`
3. run `scan --execution-mode validate`
4. export HTML and SARIF
5. replay the session if needed

### Targeted tool-abuse workflow

1. run recon and look for tools
2. run `toolabuse.*` modules
3. use a stronger attacker model if evolution is enabled
4. inspect evidence verdicts carefully

### Research workflow

1. enable research modules explicitly
2. use `--execution-mode research`
3. expect more exploratory output
4. separate those results from validation-grade reporting

## Where to Go Next

- [Desktop Advanced Guide](desktop-advanced-guide.md)
- [Eval, Probes, and Curiosity](eval-probes-curiosity.md)
- [CLI Reference](cli-reference.md)
