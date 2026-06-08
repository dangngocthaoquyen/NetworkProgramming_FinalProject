# CVE Lookup Skill

## Role

Perform offline CVE candidate lookup for validated enumeration services.

## Input

- Valid `EnumInput` that passed the permission gate.
- Local `data/cve_mock_db.json`.

## Output

- Valid JSON `AgentResult` containing CVE candidate findings.

## Allowed Tools

- Local JSON reads, Pydantic validation, and version comparison.

## Safety Constraints

- No Internet API calls and no target scanning.
- Never scan a public target.
- No exploit, payload, brute force, DoS, stress testing, or intrusive actions.
- Do not invent CVEs or evidence.
- JSON output must be valid and schema-compatible.
