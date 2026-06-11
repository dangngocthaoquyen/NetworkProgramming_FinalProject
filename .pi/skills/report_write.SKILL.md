---
name: report-write
description: Writes structured Phase 3 vulnerability reports from normalized findings, evidence, severity, and remediation data.
---

# Report Writing Skill

## Role

Render real merged pipeline results and optional host OS inventory into the
final authorized scan report.

## Input

- Valid `VulnerabilityOutput`, enum scope, and agent results.

## Output

- `.pi/outputs/ket_qua.md` generated from the real pipeline.

## Allowed Tools

- Local Markdown rendering and authorized filesystem writes.

## Safety Constraints

- Do not scan or contact any target, including public targets.
- No exploit, payload, brute force, DoS, stress testing, or intrusive actions.
- Do not invent findings, evidence, scope, or remediation.
- When JSON is requested, output must be valid structured JSON.
