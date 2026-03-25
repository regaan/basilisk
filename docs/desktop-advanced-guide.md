# Desktop Advanced Guide

This guide is for operators who want to use the Basilisk desktop app as a full local control console rather than a simple launcher.

Use Basilisk only on systems you own or are explicitly authorized to test.

## How the Desktop App Is Structured

The desktop application has three layers:

1. Electron shell
2. local Basilisk backend API
3. shared scan runtime

The important point is that the desktop app does not run a separate scan engine. It drives the same runtime as the CLI, then renders the session, evidence, and reporting state locally.

## Operator Workflow in the Desktop App

The most important tabs for advanced work are:

- `New Scan`
- `Sessions`
- `Modules`
- `Evolution`
- `Diff`
- `Probes`
- `Eval`
- `Posture`
- `Reports`
- `Audit`
- `Settings`

If you treat the app like a workflow, it usually looks like:

1. inspect modules
2. plan the scan in `New Scan`
3. monitor progress and findings
4. review the session
5. export a report
6. inspect the audit trail

## New Scan: Advanced Use

`New Scan` is the most important screen because it is where operator policy gets attached to the run.

### Target Section

Fields:

- `Endpoint URL`
- `Provider`
- `Model`
- `API Key`

This is the transport and target identity layer. If you get these wrong, the rest of the scan is noise.

### Parameters Section

Main controls:

- `Scan Mode`
- `Generations`
- `Output`
- `Include research-tier modules`
- `Skip reconnaissance phase`

Use these as runtime-shape controls, not governance controls.

### Attacker Brain

This configures evolution separately from the target:

- attacker provider
- attacker model
- attacker API key
- population size
- fitness threshold
- stagnation limit

Use it when you want a different model to drive mutation search than the model you are attacking.

### Evolution Enhancements

This section controls the evolution engine:

- diversity mode
- intent weight
- exit on first breakthrough
- response cache

Use it when:

- you want more exploration
- you want tighter intent preservation
- you want to shorten runs after the first strong result

## Campaign Control Plane

This is the core governance layer in the desktop app.

It is not decorative. It feeds the runtime and ends up in sessions and reports.

### Campaign Metadata

Fields:

- campaign name
- operator
- ticket
- target owner
- objective
- hypothesis

Use them to answer:

- who ran this
- why they ran it
- under what authorization
- against which target owner

### Policy Controls

Fields:

- execution mode
- evidence threshold
- aggression
- concurrency
- request budget
- rate limit delay
- raw evidence mode
- retention days
- scope targets
- allow modules
- deny modules
- dry run
- approval required
- approval confirmed
- retain raw findings
- retain conversations

This is the difference between “run a scan” and “run an operator-controlled campaign.”

### What These Fields Mean in Practice

`execution mode`

- `recon`: learn only
- `validate`: evidence-first
- `exploit_chain`: stronger chained behavior
- `research`: exploratory mode

`evidence threshold`

- how strong the proof must be before a result remains high or critical

`aggression`

- how hard the runtime pushes, relative to the chosen workflow

`request budget`

- hard ceiling for runs where cost or volume matters

`raw evidence mode`

- whether reports and stored artifacts should favor redaction or raw material

`allow modules` and `deny modules`

- the fastest way to scope a run when you know exactly what you want to test

## Sessions: The Most Important Review Screen

Advanced users should spend more time in `Sessions` than on the dashboard.

Each session can show:

- campaign summary
- operator and ticket
- execution mode and evidence threshold
- retention settings
- evidence verdict counts
- exploit graph summary
- phase timeline
- findings table
- downgrade summary when findings were reduced by policy

This is where you separate:

- raw noise
- useful findings
- defensible findings

### What to Look For

When you review a session, ask:

- did this run use production, beta, or research modules
- are any findings downgraded
- what evidence verdicts dominate the session
- does the exploit graph match the goal of the run
- is retention configured the way you intended

## Modules: Reading the Catalog Correctly

The `Modules` tab is where the trust-tier model becomes visible.

Each module card exposes:

- name
- category
- OWASP mapping
- trust tier
- default-on or default-off behavior

Expanded detail exposes:

- success criteria
- required proof

That matters because the current catalog is intentionally mixed:

- 11 production modules
- 18 beta modules
- 4 research modules

### How to Use the Catalog

For tight validation:

- prefer production modules first

For broader exploration:

- add beta modules deliberately

For experimental work:

- opt into research modules and label the session accordingly

## Current Module Families

### Injection and Guardrail Pressure

Production-heavy family:

- `injection.direct`
- `injection.indirect`
- `injection.encoding`
- `injection.split`
- `injection.multilingual`
- `guardrails.roleplay`
- `guardrails.logic_trap`
- `guardrails.encoding_bypass`
- `guardrails.systematic`

Use these when you want direct signal on prompt override and guardrail resistance.

### Sensitive Disclosure and Extraction

Production:

- `extraction.translation`
- `extraction.role_confusion`

Beta or research:

- simulation, gradient walk, training data exfil, RAG exfil, tool schema, knowledge enumeration

Use these when the question is whether the target leaks instructions, retrieved content, or sensitive scaffolding.

### Tool Abuse

Beta:

- SSRF
- SQLi
- command injection
- chained tool abuse

Use these only when tools are actually present or suspected from recon.

### Multi-Turn

Mostly beta, with one research module:

- cultivation
- escalation
- persona lock
- sycophancy
- authority escalation
- memory manipulation

Use these when single-turn testing is too shallow for the target.

### DoS, RAG, Multimodal

These families are useful when:

- context length matters
- retrieval matters
- the target accepts images or multimodal inputs

## Probes and Eval Tabs

### Probes

Use `Probes` when you want to inspect the YAML corpus before using it operationally.

The probe data includes:

- category
- severity
- tags
- objective
- expected signals
- failure modes
- follow-up probe IDs

This is useful when you are building a narrow campaign and want to understand the seed material rather than trust the default selection blindly.

### Eval

Use `Eval` when you already know the test cases and want assertion-driven evaluation rather than exploratory scanning.

This is the right tab for:

- refusal checks
- regression suites
- release gating
- targeted policy verification

## Diff and Posture Tabs

### Diff

Use `Diff` when your question is comparative:

- which provider resists better
- which model variant is weaker
- which category diverges across targets

### Posture

Use `Posture` when your question is:

- how strict is this target
- where do the guardrails appear thin
- what does the overall posture look like without a full campaign

## Reports

The `Reports` tab exports from saved sessions.

Formats:

- HTML
- JSON
- SARIF
- PDF

Use HTML for analyst review, SARIF for pipeline tooling, JSON for internal automation, and PDF when you need a static deliverable.

## Audit

The `Audit` tab is where you inspect the recorded event trail.

Use it to answer:

- when the scan started
- when prompts were sent
- when findings were recorded
- whether evolution ran
- when the report was generated

This is especially useful when you need to explain how a result was reached rather than only show the final finding.

## Settings and Secret Store

The settings flow surfaces:

- provider key storage
- current secret store backend
- stored provider status

Use it to avoid retyping keys into every scan.

## Recommended Advanced Desktop Workflows

### Production-style validation workflow

1. inspect the module catalog
2. keep research modules disabled
3. set `execution mode` to `Validate`
4. set `evidence threshold` to `Strong` or `Confirmed`
5. review `Sessions` before exporting

### Tool-abuse workflow

1. use recon first
2. verify tools are exposed
3. use allowlists to scope modules to tool abuse families
4. watch evidence verdicts and downgrade state carefully

### Multi-turn workflow

1. run a normal validation pass first
2. shift to multi-turn modules only when single-turn evidence is weak or target behavior is contextual
3. review transcripts and phase history in `Sessions`

## Common Mistakes

### Treating the dashboard as the main evidence view

The dashboard is a summary. `Sessions` is the evidence review surface.

### Mixing research modules into routine validation

If you want clean operational output, keep research modules out unless you explicitly need them.

### Leaving governance fields blank

If you skip operator, ticket, objective, and target owner, the run still works, but the session is much less useful later.

## Where to Go Next

- [CLI Advanced Guide](cli-advanced-guide.md)
- [Eval, Probes, and Curiosity](eval-probes-curiosity.md)
- [Architecture](architecture.md)
