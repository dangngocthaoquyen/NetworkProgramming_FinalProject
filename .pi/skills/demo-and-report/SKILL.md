---
name: demo-and-report
description: Rehearse and verify the Topic 06 Phase 3 demo package, including artifact verification, evidence collection, report checklist review, command validation, and presentation notes. Use when preparing grading demos, checking vuln.json/report/log outputs, or assembling presentation-ready evidence rather than coordinating the main pipeline logic itself.
---

# Demo and Report

## Purpose
Giúp chạy demo ổn định trên Windows, kiểm tra artifact đầu ra, và chuẩn bị evidence để chấm đồ án.

## When to Use
Dùng skill này khi cần demo toàn pipeline, soát checklist artifact, kiểm tra command pass/fail, hoặc chuẩn bị phần trình bày/báo cáo cuối.

Đọc thêm:
- [Demo Script](references/demo-script.md)
- [Report Checklist](references/report-checklist.md)
- [Presentation Notes](references/presentation-notes.md)

## Inputs
- Sample `enum.json` hoặc `data/pi/enum.json`.
- Môi trường Python của project.
- `config.yaml`.

## Outputs
- Artifact demo có thể kiểm tra được.
- Danh sách command đã chạy và trạng thái pass/fail.
- Ghi chú rõ ràng nếu thiếu dependency như `pytest` hoặc Nuclei binary.

## Workflow
1. Xác nhận sample input hợp lệ.
2. Chạy test nếu môi trường có dependency.
3. Chạy pipeline sample.
4. Kiểm tra `vuln.json`, `report.md`, `triage/*`, và log.
5. Chụp các điểm evidence cần nói khi thuyết trình.

## Checklist
- `enum.json` hợp lệ
- agent outputs sinh ra
- `vuln.json` sinh ra
- report sinh ra
- log/timing chứng minh parallelism
- test/demo command pass hoặc có giải thích fail rõ ràng

## Honest Demo Rule
Nếu phiên demo chỉ dùng offline-safe mock/fixture, phải nói rõ đó là chế độ demo an toàn trong lab.
