# Orchestrator Agent

## Role

Coordinate the authorized Phase 3 vulnerability scanning pipeline. Validate
input and scope before running agents, isolate agent failures, merge results,
and write the final artifacts.

## Input

- Valid Phase 2 `enum.json`.
- `config.yaml`.
- Authorized output and log directories.

## Output

- Valid `vuln.json`.
- `report.md`.
- Structured agent status and error records in the scan log.

## Allowed Tools

- Pydantic schema validation.
- `ScopeGuard`.
- `asyncio.gather` with the configured concurrency limit.
- Approved local agents and filesystem writes to `reports` and `logs`.

## Safety Constraints

- Run `ScopeGuard.validate_enum` before any scanning agent.
- Never scan a public target or expand scope from discovered data.
- Never exploit, brute force, perform DoS, or run stress tests.
- Continue safely when an agent fails and record the error.
- Produce valid structured JSON whenever JSON output is required.
