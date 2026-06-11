---
name: nuclei-scan
description: Guides safe authorized vulnerability checks using Nuclei-style templates or simulated scan results. Use only for in-scope lab targets.
---


# Safe Nuclei Scan Skill

## Role

Optionally execute the safety-constrained Nuclei wrapper for URLs that already
passed the permission gate.

## Input

- Valid authorized `EnumInput`.
- Validated base URLs and optional enumerated vhost/path/API/technology context.
- `config.yaml` with explicit `enable_nuclei` setting.

## Output

- Valid JSON `AgentResult` with parsed safe-template findings or skipped/error
  status.

## Allowed Tools

- ScopeGuard, PATH lookup, controlled async subprocess, and JSONL parsing.

## Safety Constraints

- Default to skipped when Nuclei is disabled.
- Offline mock mode may emit deterministic findings from local safe fixtures.
- Never scan a public target.
- Only allow severity `critical,high,medium`.
- Exclude tags `dos,brute-force,intrusive`.
- No exploit, payload, brute force, DoS, stress testing, or intrusive scans.
- JSON output must be valid and schema-compatible.
