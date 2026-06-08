# Structured JSON Output

## Role

Define reliable JSON contracts for communication between agents and for final
pipeline artifacts.

## Input

- Agent results, findings, summaries, and validated Pydantic models.

## Output

- Valid JSON conforming to the shared schemas.
- Deterministic fields suitable for merge, scoring, logging, and reporting.

## Allowed Tools

- Pydantic v2 validation and serialization.
- Python standard-library JSON parsing and serialization.
- Local schema tests.

## Safety Constraints

- Never include secrets, API keys, tokens, or passwords.
- Never scan a public target.
- Never add or expand public scan targets in generated JSON.
- Never encode exploit, brute-force, DoS, or stress-test instructions.
- Reject malformed or unexpected fields according to the active schema.
- JSON output must be syntactically valid whenever JSON is required.
- Preserve evidence and source-agent attribution without inventing data.
