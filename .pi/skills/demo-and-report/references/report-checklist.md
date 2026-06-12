# Report Checklist

## Must Verify
- `enum.json` đọc được và đúng schema.
- `vuln.json` được sinh ra.
- `report.md` trong output directory được sinh ra.
- `cve_candidates.json` có mặt.
- `nuclei_results.json` có mặt.
- `pipeline.log` hoặc `logs/<scan>.log` có `agent_timing`.

## Report Quality Checks
- Scope phải ghi rõ authorized lab/private only.
- Finding phải có severity, confidence, evidence, remediation.
- Không viết như thể đã scan public target.
- Nếu mock mode, phải ghi chú trung thực.
