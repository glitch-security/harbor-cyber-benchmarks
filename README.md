# HARBOR Cyber Benchmarks

A curated showcase of **cybersecurity benchmark tasks** (HARBOR / cyber-bench
format) curated by Matrix Security Solutions. Each task is a self-contained, agentic security
challenge that runs against an **isolated local environment** with no internet
access, scored by a **behavioral verifier** that checks real effects rather than
response text.

The collection is split into two suites:

| Suite | What it measures | Tasks |
|---|---|---|
| [**Offensive datasets**](offensive-datasets/) | Can an agent discover and chain real weaknesses to produce a scored effect (SSRF, cross-tenant data exfiltration, HTTP request-integrity abuse)? | 3 |
| [**Defensive datasets**](defensive-datasets/) | Can an agent harden code, fix vulnerabilities, or produce correct analytical findings? | — (reserved) |

## How a task is structured

Every task directory contains a full, reproducible package:

```
<suite>/<task>/rev_1__<id>/
├── task_files/
│   ├── instruction.md     the brief given to the agent
│   ├── task.toml          metadata, resource limits, verifier/agent config
│   ├── solution/          validated reference solution (the exploit / fix)
│   ├── tests/             the behavioral verifier
│   └── environment/       everything needed to build the isolated target
├── evaluations/           one folder per model run — result.json (scores),
│                          agent trajectory, and captured agent I/O
└── verifications/         independent QC review of the task
```

## Scoring at a glance

- **binary_reward** is the headline pass/fail: a declarative proof is replayed
  from clean state (usually twice) and must reproduce the scored effect.
- **continuous_reward** and its components (`validity`, `output_quality`,
  `process`, `deterministic`) give partial-credit detail for ranking near-misses;
  they do not change pass/fail.
- An **oracle** run (the reference solution) is included per task as the ground
  truth that the challenge is solvable — it scores 1.00.

## Current results

Across the three offensive tasks, every evaluated frontier model
(`gpt-6-sol`, `gpt-5.6-sol`, `gemini-3.5-flash`, via the `terminus-2` harness)
**failed to solve any task**; only the reference oracle passes. Per-model score
tables and failure analysis live in each task's README.

## Safety & authorization

All targets are sandboxed, local-only benchmark environments built specifically
for evaluation. Reference exploits are included solely as the scoring ground truth
for these isolated targets. The material is intended for authorized security
research, benchmarking, and education.
