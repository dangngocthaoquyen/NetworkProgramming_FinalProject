---
name: vuln-merge-rank
description: Normalize findings after the agents have finished by performing post-agent merge, deduplicate, severity normalization, and risk ranking for Topic 06 Phase 3 output generation. Use when preparing vuln.json from completed agent results, reviewing dedup keys and source_agents behavior, or explaining current ranking and cross-agent correlation limits rather than orchestrating the full pipeline.
---

# Vulnerability Merge and Rank

## Purpose
Chuẩn hóa cách gộp kết quả từ nhiều agent và biến chúng thành danh sách vulnerability candidates có thể demo và báo cáo được.

## When to Use
Dùng skill này khi làm việc với `deduplicate.py`, `scoring.py`, logic sort/rank trong orchestrator, hoặc khi cần giải thích chính xác project hiện dedup và ranking như thế nào.

Đọc thêm:
- [Dedup Policy](references/dedup-policy.md)
- [Ranking Policy](references/ranking-policy.md)
- [Source Trace Policy](references/source-trace-policy.md)

## Inputs
- Danh sách findings đã validate từ các agent.
- `source_agents`, `source_type`, `host`, `port`, `cve_id`, `title`, `evidence`, `confidence`, `cvss`.

## Outputs
- Findings đã deduplicate theo logic hiện có của project.
- `risk_score` và severity đã được chuẩn hóa.
- Danh sách đã sort giảm dần theo mức ưu tiên.

## Workflow
1. Validate từng finding vào schema chung.
2. Dedup theo key hiện có của codebase.
3. Merge `source_agents`, `evidence`, `remediation`, đồng thời lấy `cvss` và `confidence` phù hợp.
4. Tính `risk_score`.
5. Chuẩn hóa severity từ `cvss`.
6. Sinh `finding_id` cuối theo host/port/source_type.

## Important Honesty Rule
Không được mô tả rằng project đã có cross-agent semantic correlation mạnh nếu code hiện tại chưa làm điều đó. Project hiện có dedup/rank thật, nhưng correlation giữa CVE lookup và Nuclei còn giới hạn.
