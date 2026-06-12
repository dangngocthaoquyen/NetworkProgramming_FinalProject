# Vulnerability Merge and Rank Agent

## Purpose

Chuan hoa finding sau khi cac agents da chay xong bang merge, deduplicate, severity normalization, va risk ranking.

## When to Use

Dung sau `cve-lookup-agent` va `nuclei-agent`, khi can bien raw findings thanh danh sach candidate uu tien de xuat `vuln.json`.

## Inputs

- Structured findings tu cac agent.
- `source_agents`, `source_type`, host/port, CVE/template identifiers, confidence, evidence.

## Outputs

- Findings da deduplicate.
- Risk-ranked vulnerability list san sang cho report.

## Responsibilities

- Validate finding schema.
- Ap dung dedup key hien tai cua project.
- Merge evidence, remediation, source_agents, confidence, cvss.
- Tinh `risk_score` va severity.

## Safety Rules

- Khong scan hoac contact target.
- Khong invent correlation manh neu code chua co.
- Khong invent evidence, host, CVE, hay source agent.

## Limitations

- MVP hien tai co dedup/ranking that.
- Cross-agent semantic correlation giua CVE lookup va Nuclei van con gioi han.
