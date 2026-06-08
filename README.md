# Phase 3 - Vulnerability Scanning MVP

Scaffold Python cho Phase 3 cua bai tap pentest: nhan ket qua enumeration cua
target lab da duoc uy quyen, dieu phoi cac buoc vulnerability scanning an toan,
chuan hoa finding, gop ket qua va tao bao cao.

## Pham vi an toan

- Chi scan target ma ban co uy quyen ro rang.
- Cau hinh mac dinh chi cho phep localhost va cac mang private:
  `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
- Public IP bi chan mac dinh.
- `max_concurrency` duoc gioi han o `5`.
- Nuclei bi tat mac dinh.
- Project khong thuc hien exploit, brute force, DoS hoac scan Internet public.

## Cau truc

- `app/agents`: dieu phoi workflow scanning.
- `app/schemas`: schema cho input, finding va report.
- `app/tools`: wrapper an toan cho cac scanner duoc phep.
- `app/merge`: chuan hoa, loai trung va gop finding.
- `app/reports`: tao bao cao.
- `data/samples`: input enumeration mau cho Phase 3.
- `tests`: kiem tra guardrail va hanh vi cua project.

## Cai dat va chay

Tao virtual environment, cai dependency va chay smoke test:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest
```

Chay Phase 3 voi sample lab:

```powershell
python run_phase3.py --enum data/samples/enum_lab.json --out reports/scan-001
```

Chay theo format Pi/multi-agent:

```powershell
python run_phase3.py --enum .pi/data/enum.json --out .pi/outputs
```

Moi lan chay pipeline tao artifact tai thu muc `--out` va dong thoi ghi ket qua
that cua pipeline vao:

- `.pi/outputs/vuln.json`: findings da merge va risk-ranked.
- `.pi/outputs/ket_qua.md`: bao cao Markdown cuoi.
- `.pi/outputs/cve_candidates.json`: ket qua that cua CVE Lookup Agent.
- `.pi/outputs/nuclei_results.json`: ket qua that cua Nuclei Agent, thuong la
  `skipped` khi Nuclei dang tat.
- `.pi/logs/pipeline.log`: trang thai va loi cua cac agent.

Lenh sample thuong cung tao `reports/scan-001/vuln.json`,
`reports/scan-001/report.md` va `logs/scan-001.log`, sau do in summary bang
Rich.

Input mau nam tai `data/samples/enum_lab.json`. Truoc khi bo sung bat ky scanner
nao, hay validate target theo allowlist trong `config.yaml` va dung ngay neu
target la public IP hoac khong co uy quyen.

Moi enumeration input phai duoc kiem tra bang `ScopeGuard.validate_enum` truoc
khi agent scan chay. Guard doc `safety.allowed_cidrs` va `block_public_ip` tu
`config.yaml`, dong thoi chan IP public, IP ngoai allowlist va hostname resolve
ra dia chi khong duoc phep.

`CveLookupAgent` thuc hien lookup offline tu `data/cve_mock_db.json`, khong goi
API Internet. Agent chi tra ve cac match co CVSS tu `7.0` tro len va gan
confidence theo muc do khop product/version.

`NucleiAgent` mac dinh tra ve `skipped` vi `enable_nuclei: false`. Khi duoc bat
ro rang, agent chi chay URL da qua scope guard, chi cho phep severity
`critical,high,medium`, va loai tru tag `dos,brute-force,intrusive`. Loi binary,
subprocess hoac timeout duoc tra ve trong `AgentResult` thay vi lam crash
pipeline.

Pipeline deduplicate finding theo `host`, `port`, `cve_id` va `title`, dong
thoi merge `source_agents` va evidence. Risk score duoc tinh theo
`cvss * 10 * confidence`, cong them `5` khi co Nuclei confirmation va gioi han
toi da `100`. Report Markdown gom Executive Summary, Scope, Findings by
Severity, Technical Details, Remediation va Appendix.

## Luu y uy quyen

Chi su dung project trong lab, CTF, hoac he thong co van ban uy quyen. Nguoi
van hanh chiu trach nhiem xac minh pham vi va phe duyet truoc khi scan.
Project khong scan public Internet va khong tu mo rong pham vi target.
