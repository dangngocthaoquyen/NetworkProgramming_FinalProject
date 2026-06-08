# AGENTS.md

## Project Overview

- This repository implements Phase 3 of a pentesting pipeline: Vulnerability
  Scanning.
- The input is `enum.json` produced by the enumeration phase.
- The outputs are `vuln.json` and `report.md`.
- This project is only for vulnerability scanning of explicitly authorized
  targets.

## Tech Stack

- Python 3.11+
- Pydantic v2
- `asyncio`
- PyYAML
- Rich
- pytest
- Optional Nuclei wrapper, disabled by default

## Repository Layout

- `app/schemas`: Pydantic schemas and structured data contracts.
- `app/agents`: Agent orchestration and scanning workflow logic.
- `app/tools`: Safe wrappers around approved scanning tools.
- `app/merge`: Finding normalization, deduplication, and merge logic.
- `app/reports`: Vulnerability report generation.
- `data/samples`: Authorized lab sample inputs and outputs.
- `reports`: Generated reports.
- `logs`: Raw scanner output, logs, and artifacts.
- `tests`: Automated tests.
- `.pi`: Existing project support directory.

## Security and Safety Rules

- Never scan the public Internet.
- Only allow localhost, private CIDRs, and explicitly authorized lab networks.
- Never write or execute exploits.
- Never perform brute force attacks.
- Never perform DoS, stress testing, or resource exhaustion.
- Never automatically run intrusive scanner templates.
- Never hardcode API keys, tokens, passwords, or other secrets.
- Never delete files, databases, reports, or artifacts without explicit
  confirmation.
- Nuclei must default to `enable_nuclei: false`.
- Every target must pass `scope_guard` before any scanning agent runs.
- Do not expand scan scope based on LLM decisions or discovered targets.

## Development Rules

- Validate all external and inter-agent data with Pydantic schemas.
- Use structured JSON for communication between agents.
- An individual agent failure must not crash the entire pipeline.
- Run independent agents in parallel with `asyncio.gather`, always protected by
  a configured concurrency limit.
- Preserve raw scanner output in `logs` or an artifacts location when
  available.
- Keep agent, tool, merge, and report logic clearly separated.
- Do not allow an LLM to independently expand the authorized scan scope.

## Definition of Done

- The code runs successfully.
- Relevant pytest coverage is included.
- Verification commands are documented or provided.
- Existing schemas and their compatibility are not broken.
- Update README or documentation when behavior changes.
- The final response clearly lists changed files and explains how to verify the
  change.

## How Codex Should Work

- Before substantial changes, read `AGENTS.md`, `README.md`, `config.yaml`, and
  the schemas in `app/schemas`.
- Small, well-scoped changes may be implemented directly.
- For changes involving architecture, scan scope, scanner subprocesses, or
  safety guards, propose a short plan before editing.
- Always run pytest after making changes.
- Never create code capable of attacking targets outside an authorized lab.
