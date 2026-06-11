---
name: cve-lookup
description: Looks up offline CVE candidates from OS, service, and version fingerprints. Use for Phase 3 vulnerability matching.
---

# CVE Lookup Skill

## Role

Perform offline CVE candidate lookup for validated enumeration services and
optional host OS fingerprints supplied by earlier phases.

## Input

- Valid `EnumInput` that passed the permission gate, including optional OS
  name/version/kernel/build and CPE metadata.
- Local `data/cve_mock_db.json`.

## Output

- Valid JSON `AgentResult` containing service and OS CVE candidate findings
  with explicit `source_type`.

## Allowed Tools

- Local JSON reads, Pydantic validation, and version comparison.

## Safety Constraints

- No Internet API calls and no target scanning.
- Never scan a public target.
- No exploit, payload, brute force, DoS, stress testing, or intrusive actions.
- Do not invent CVEs or evidence.
- JSON output must be valid and schema-compatible.
