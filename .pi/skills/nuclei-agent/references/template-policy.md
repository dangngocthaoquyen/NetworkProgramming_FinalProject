# Template Policy

## Current Project Position
- Project ưu tiên offline-safe mock mode cho demo.
- Real Nuclei mặc định tắt trong `config.yaml`.

## Severity Policy
- Mục tiêu của project là severity `critical` và `high`.
- Khi mô tả skill này, dùng ngôn ngữ nhất quán với yêu cầu đề tài: web CVE/misconfiguration templates ở mức `critical/high`.

## Exclusion Policy
- Loại trừ tag `dos`, `brute-force`, `intrusive`.
- Không thêm hướng dẫn template tấn công public target.

## Honest Demo Notes
- Nếu phiên chạy chỉ dùng local fixture `data/nuclei_mock_db.json`, phải ghi rõ là offline-safe mock.
- Real mode cần Nuclei binary trong `PATH` và template phù hợp, nhưng không bắt buộc cho demo lab-ready hiện tại.
