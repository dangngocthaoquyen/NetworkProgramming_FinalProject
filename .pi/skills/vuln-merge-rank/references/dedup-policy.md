# Dedup Policy

## Current Dedup Key
Code hiện dedup theo:
- `host`
- `port`
- `cve_id` hoặc `finding_id`
- `title`
- `source_type`

## Current Merge Behavior
Khi trùng key:
- Gộp `source_agents`
- Gộp `evidence`
- Gộp `remediation`
- Lấy `cvss` lớn hơn
- Lấy `confidence` lớn hơn

## Current Limitation
- Nếu Nuclei finding và CVE finding khác `source_type`, khác `title`, hoặc một bên không có `cve_id`, chúng thường không merge thành một finding chung.
- Vì vậy không nên claim đã có cross-agent correlation mạnh.

## Source of Truth
Xem `../../../app/merge/deduplicate.py`.
