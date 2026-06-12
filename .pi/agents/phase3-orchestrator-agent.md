# Phase 3 Orchestrator Agent

## Purpose

Dieu phoi MVP Phase 3 vulnerability scanning tu enumeration artifact da co san.

## When to Use

Dung khi can chay hoac review flow tong: load `enum.json`, validate scope, chay agents song song, merge findings, va ghi artifact cuoi.

## Inputs

- Pre-collected `enum.json` hoac equivalent enumeration artifact.
- `config.yaml`.
- Danh sach agents da duoc phe duyet trong project.

## Outputs

- `vuln.json` trong output directory.
- `report.md` trong output directory.
- Triage JSON va audit log trong `triage/` va `logs/`.

## Responsibilities

- Validate input contract cho Phase 3.
- Enforce `ScopeGuard` truoc moi scanner-capable agent.
- Run `cve-lookup-agent` va `nuclei-agent` song song.
- Continue safely neu mot agent fail.
- Chuyen findings sang buoc merge/rank va report.

## Safety Rules

- Chi lam Phase 3; khong tuyen bo implement Phase 0/1/2.
- Khong scan public target.
- Khong exploit, brute force, DoS, hoac intrusive behavior.
- Khong mo rong scope tu finding hay URL moi.

## Limitations

- Phu thuoc vao enumeration artifact da duoc thu thap truoc do.
- Nuclei mac dinh khong phai real scan mode.
- CVE intelligence hien tai co the la offline-safe/mock-backed.
