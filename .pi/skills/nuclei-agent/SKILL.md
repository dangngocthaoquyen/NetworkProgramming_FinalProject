---
name: nuclei-agent
description: Run or review the project's Nuclei-based web vulnerability agent for Topic 06 Phase 3 scanning. Use when working with authorized lab URLs from enum.json, web CVE or misconfiguration checks, severity critical/high filtering, offline-safe mock mode, or real mode requirements such as the Nuclei binary and validated in-scope targets.
---

# Nuclei Agent

## Purpose
Hướng dẫn vận hành agent web vulnerability scanning dựa trên Nuclei hoặc mock Nuclei của project.

## When to Use
Dùng skill này khi làm việc với `nuclei-agent`, khi cần chạy demo web CVE/misconfiguration checks, khi cần xác minh scope cho URL trong lab, hoặc khi cần giải thích khác biệt giữa mock mode và real mode.

Đọc thêm:
- [Nuclei Scope Policy](references/nuclei-scope-policy.md)
- [Template Policy](references/template-policy.md)
- [Output Contract](references/output-contract.md)

## Inputs
- `EnumInput` hợp lệ đã có URL/web context.
- `config.yaml`.
- URL, `vhost`, `technologies`, `discovered_paths`, `api_endpoints` từ phase trước.

## Outputs
- `AgentResult` với `success`, `partial`, `failed`, hoặc `skipped`.
- Findings merge-ready với `source_type: web-template`.

## Workflow
1. Validate enum và scope trước.
2. Lấy danh sách URL đã trong scope.
3. Nếu `enable_nuclei_mock: true`, ưu tiên mock mode an toàn của project.
4. Nếu mock không trả gì và `enable_nuclei: false`, trả `skipped`.
5. Nếu real mode được bật rõ ràng, kiểm tra Nuclei binary rồi chạy subprocess có filter an toàn.
6. Parse JSONL findings vào schema chung.

## Safety Notes
- Chỉ chạy với private/lab targets đã qua allowlist.
- Chỉ chấp nhận severity `critical` và `high` theo behavior mục tiêu của project.
- Nói trung thực rằng mock mode hiện hữu để demo an toàn; real mode cần Nuclei binary/templates và môi trường phù hợp.
