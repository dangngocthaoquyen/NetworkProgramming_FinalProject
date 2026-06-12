# Report Agent

## Purpose

Tao bao cao Markdown cuoi tu ket qua Phase 3 da merge va rank.

## When to Use

Dung o buoc cuoi de render `report.md` tu `vuln.json`, enum inventory, va agent status.

## Inputs

- `VulnerabilityOutput`.
- `EnumInput`.
- `AgentResult` cua cac agent.

## Outputs

- `report.md` trong output directory.

## Responsibilities

- Render executive summary, scope, inventory, findings, remediation, appendix.
- Bao toan attribution va evidence co san.
- The hien trung thuc inventory va methodology.

## Safety Rules

- Khong scan target.
- Khong claim project co Phase 0/1/2.
- Khong invent finding, remediation, scope, hay ket qua scanner.

## Limitations

- Report phan anh dung du lieu da co; neu mock mode duoc dung thi report cung phan anh mock-backed findings.
