# Phase 3 - Vulnerability Scanning MVP

Scaffold Python cho Phase 3 cua bai tap pentest: nhan `enum.json` tu Phase 1
reconnaissance va Phase 2 scanning cua target lab da duoc uy quyen, dieu phoi
cac buoc vulnerability assessment an toan, chuan hoa finding, gop ket qua va
tao bao cao. Project khong trien khai lai Phase 1 hoac Phase 2.

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

Ba sample tap trung de kiem tra tuong thich va OS assessment:

```powershell
python run_phase3.py --enum data/samples/enum_lab_no_os.json --out outputs/test_no_os
python run_phase3.py --enum data/samples/enum_lab_linux_os.json --out outputs/test_linux_os
python run_phase3.py --enum data/samples/enum_lab_windows_os.json --out outputs/test_windows_os
python run_phase3.py --enum data/samples/enum_lab_full.json --out outputs/test_full
```

`enum_lab_full.json` la demo artifact day du tu Phase 1 + Phase 2, gom nhieu
host private lab, OS fingerprint, open ports, service/product/version, URL,
vhost, CPE, technologies, discovered paths, API endpoints, nguon enumeration,
confidence va banner. Phase 3 chi tieu thu artifact nay; khong tu thuc hien
reconnaissance, DNS enumeration, dirbust hoac port scanning.

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

Moi host trong `enum.json` co the co object `os` tuy chon voi name, version,
kernel, build, architecture, patch level, confidence va source. Phase 3 chi
dung fingerprint OS nay de lookup vulnerability candidate offline va bao cao
rui ro; project khong tu fingerprint OS, khong exploit va khong mo rong scope.

- Service-level findings duoc xac dinh tu service, product va version.
- OS-level findings duoc xac dinh tu OS name, version, kernel va build.
- Nuclei/template findings duoc danh dau `source_type: web-template`.
- `cve-lookup-agent` dua CPE vao evidence khi Phase 1/2 cung cap.
- `nuclei-agent` dung URL da validate cung vhost, discovered paths, API
  endpoints va technologies trong offline safe fixture; khong tu discover
  target moi.
- Phase 3 chi nhan dien, merge va xep hang vulnerability candidates; khong khai
  thac vulnerability.

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

Pipeline deduplicate finding theo `host`, `port`, `cve_id`, `title` va
`source_type`, dong thoi merge `source_agents` va evidence. Risk score duoc tinh theo
`cvss * 10 * confidence`, cong them `5` khi co Nuclei confirmation va gioi han
toi da `100`. Report Markdown gom Executive Summary, Scope, Findings by
Severity, Technical Details, Remediation va Appendix.

Severity trong `vuln.json` duoc chuan hoa theo CVSS: `critical` tu 9.0,
`high` tu 7.0, `medium` tu 4.0, `low` tren 0 va `info` tai 0. Moi finding co
`finding_id` xac dinh theo CVE/template, host, port hoac OS, va source type.
Full demo dung fixture web-template offline an toan; real Nuclei van bi tat mac
dinh.

## Luu y uy quyen

Chi su dung project trong local lab, CTF, hoac he thong co van ban uy quyen.
Nguoi van hanh chiu trach nhiem xac minh pham vi va phe duyet truoc khi scan.
Project khong scan public Internet va khong tu mo rong pham vi target.
Project khong exploit, brute force, DoS hoac chay intrusive scan.
