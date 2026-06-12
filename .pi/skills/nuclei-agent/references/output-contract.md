# Output Contract

## Envelope
Trả về `AgentResult` với:
- `agent_name: nuclei_agent`
- `scan_id`
- `status`
- `message`
- `data.findings`
- `errors`

## Finding Shape
Mỗi finding nên có:
- `finding_id` từ template
- `title`
- `host`
- `port`
- `source_agents: ["nuclei_agent"]`
- `source_type: web-template`
- `severity`
- `cvss`
- `confidence`
- `evidence`
- `remediation`
- `risk_score`

## Merge Notes
- Không tự claim finding này đã được correlate với CVE lookup nếu code chưa thực hiện merge semantic như vậy.
- Output cần đủ thông tin để orchestrator có thể dedup/rank theo logic hiện tại.
