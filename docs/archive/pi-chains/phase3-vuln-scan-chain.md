# Phase 3 Vulnerability Scan Chain

## Purpose

Mo ta chain orchestration cho Topic 06 Phase 3: vulnerability scanning tren pre-collected enumeration artifact.

## Steps

1. Load `enum.json` hoac equivalent pre-collected enumeration artifact.
2. Validate schema va validate scope.
3. Run CVE lookup agent.
4. Run Nuclei agent.
5. Merge va deduplicate findings.
6. Rank findings theo risk.
7. Generate `vuln.json` va `report.md`.
8. Save triage va log artifacts.

## Scope Note

Day la orchestration cho Phase 3. Chain nay khong implement va khong duoc claim la Phase 0, Phase 1, hoac Phase 2.
