# Nuclei Scope Policy

## Scope Guard
- Mọi URL phải xuất phát từ `enum.json`.
- Host của URL phải qua `ScopeGuard`.
- Không tự thêm URL mới từ suy luận của agent.

## Allowed Targets
- Localhost.
- Private CIDR.
- Authorized lab hosts theo `config.yaml`.

## Disallowed Targets
- Public IP.
- Domain resolve ra public IP.
- Mọi target ngoài allowlist.

## Source of Truth
Xem `../../../app/agents/nuclei_agent.py` và `../../../app/tools/scope_guard.py`.
