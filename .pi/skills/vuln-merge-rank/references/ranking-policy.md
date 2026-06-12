# Ranking Policy

## Risk Score
Code hiện tính:

`risk_score = (cvss or 0) * 10 * confidence`

Nếu `source_agents` có chuỗi chứa `nuclei` thì cộng bonus `5`, sau đó cap ở `100`.

## Severity Normalization
- `>= 9.0` -> `critical`
- `>= 7.0` -> `high`
- `>= 4.0` -> `medium`
- `> 0` -> `low`
- `0` hoặc `None` -> `info`

## Sorting
Findings được sort theo:
1. `risk_score` giảm dần
2. `finding_id`

## Source of Truth
Xem `../../../app/merge/scoring.py` và `../../../app/orchestrator.py`.
