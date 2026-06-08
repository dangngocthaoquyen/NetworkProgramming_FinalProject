# Risk Ranking Skill

## Role

Deduplicate findings and calculate consistent risk scores and severity.

## Input

- Valid structured findings with host, port, CVE ID, title, confidence,
  evidence, and source agents.

## Output

- Valid JSON findings deduplicated by host, port, CVE ID, and title.
- Merged source agents and evidence.
- Normalized risk score and severity.

## Allowed Tools

- Local merge/scoring modules and Pydantic validation.

## Safety Constraints

- Do not contact or scan any target, including public targets.
- No exploit, payload, brute force, DoS, stress testing, or intrusive actions.
- Do not fabricate confirmation or evidence.
- JSON output must be valid and deterministic.
