# Safe Nuclei Scan Skill

## Role

Optionally execute the safety-constrained Nuclei wrapper for URLs that already
passed the permission gate.

## Input

- Valid authorized `EnumInput`.
- `config.yaml` with explicit `enable_nuclei` setting.

## Output

- Valid JSON `AgentResult` with parsed safe-template findings or skipped/error
  status.

## Allowed Tools

- ScopeGuard, PATH lookup, controlled async subprocess, and JSONL parsing.

## Safety Constraints

- Default to skipped when Nuclei is disabled.
- Never scan a public target.
- Only allow severity `critical,high,medium`.
- Exclude tags `dos,brute-force,intrusive`.
- No exploit, payload, brute force, DoS, stress testing, or intrusive scans.
- JSON output must be valid and schema-compatible.
