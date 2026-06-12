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
- Nuclei mac dinh chay `cli` mode cho lab run, nhung van giu `mock` mode de demo offline/fallback.
- CVE lookup co the chay `mock`, `nvd_live`, hoac `auto` voi cache NVD.
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

Tren Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest
```

Chay Phase 3 voi sample lab:

```powershell
python run_phase3.py --enum data/samples/enum_lab.json --out reports/scan-001
```

Chay demo voi sample duoc import tu Nmap XML cua Metasploitable3 Ubuntu:

```powershell
python run_phase3.py --enum data/samples/enum_metasploitable3_ub1404.json --out reports/metasploitable3-demo
```

Bat NVD live mode va cung cap API key tren PowerShell:

```powershell
$env:NVD_API_KEY="your-nvd-api-key"
python run_phase3.py --enum data/samples/enum_metasploitable3_ub1404.json --out reports/metasploitable3-demo
```

Hoac dat API key trong file `.env` o root project:

```dotenv
NVD_API_KEY=your-nvd-api-key
```

Neu muon bat ro rang `nvd_live`, cap nhat `config.yaml`:

```yaml
cve_lookup:
  source: "nvd_live"
```

Khong commit API key vao repo. `.env`, `.env.*` va `data/cache/nvd/` da duoc
ignore. NVD live co rate limit; project uu tien dung cache va fallback de demo
on dinh hon.

Cai Nuclei OSS local tren Windows bang Go:

```powershell
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Neu o C: thieu dung luong, co the chuyen workspace cua Go sang `E:\` truoc khi cai:

```powershell
$env:GOPATH="E:\go"
$env:GOBIN="E:\go\bin"
$env:GOCACHE="E:\go-build"
$env:GOTMPDIR="E:\go-tmp"
New-Item -ItemType Directory -Force -Path $env:GOPATH,$env:GOBIN,$env:GOCACHE,$env:GOTMPDIR | Out-Null
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Kiem tra binary va version:

```powershell
nuclei -version
```

Mac dinh `config.yaml` da bat Nuclei CLI cho authorized lab run:

```yaml
nuclei:
  mode: "cli"
  binary: "${NUCLEI_BINARY:-nuclei}"
  severity: ["critical", "high"]
  timeout_seconds: 900.0
  use_mock_fallback: true
```

Dat binary trong `.env`:

```dotenv
NUCLEI_BINARY=E:\go\bin\nuclei.exe
```

Neu `NUCLEI_BINARY` khong duoc set, project se fallback ve gia tri mac dinh
`nuclei`, tuc la tim binary trong `PATH`.

Che do `mock` van duoc giu lai de demo offline:

```yaml
nuclei:
  mode: "mock"
```

Che do `auto` van duoc giu nguyen de uu tien CLI va fallback mock khi binary/thiet lap
chua san sang:

```yaml
nuclei:
  mode: "auto"
  use_mock_fallback: true
```

Manual CLI test cho lab Metasploitable3:

```powershell
nuclei -list E:\Metasploitable3-Lab\enum\nuclei-targets.txt -severity critical,high -jsonl -stats -no-interactsh -exclude-tags dos,brute-force,intrusive -duc -o E:\Metasploitable3-Lab\enum\nuclei-results.jsonl
```

Khi project chay `mode: "cli"`, subprocess se dung cung nhom option an toan:

- `-list <targets-file>`
- `-severity critical,high`
- `-jsonl`
- `-no-interactsh`
- `-exclude-tags dos,brute-force,intrusive`
- `-duc`
- `-o <jsonl-output>`

Nuclei CLI co the chay kha lau tren full template set, va hoan toan co the tra
`0` finding neu khong co template `critical/high` nao match. Day la ket qua hop
le, khong phai loi. Report se ghi ro `Nuclei CLI completed with 0 critical/high matches`.

Neu `mode: "cli"` nhung binary loi, timeout, hoac runtime error, agent co the
fallback sang mock khi `use_mock_fallback: true`. Neu muon fail ngay thay vi
fallback, dat:

```yaml
nuclei:
  mode: "cli"
  use_mock_fallback: false
```

Neu agent dang dung `mock` hoac fallback mock thi report se ghi ro day la
offline fixture/fallback, khong nham voi CLI ket qua that.

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

Chay theo format Pi/MVP:

```powershell
python run_phase3.py --enum data/pi/enum.json --out reports/pi-phase3
```

Moi lan chay pipeline tao artifact tai thu muc `--out` va dong thoi ghi ket qua
that cua pipeline vao cac thu muc runtime o root project:

- `reports/<scan>/vuln.json`: findings da merge va risk-ranked.
- `reports/<scan>/report.md`: bao cao Markdown cuoi.
- `triage/vuln.json`: ban sao JSON de phuc vu triage/workflow.
- `triage/cve_candidates.json`: ket qua that cua CVE Lookup Agent.
- `triage/nuclei_results.json`: ket qua cua Nuclei Agent. O che do demo
  an toan mac dinh, agent dung offline mock fixture/cache trong repo; real
  Nuclei chi chay khi duoc bat ro rang va van phai qua scope guard.
- `logs/pipeline.log`: trang thai va loi cua cac agent.

Lenh sample thuong cung tao `reports/<scan>/vuln.json`,
`reports/<scan>/report.md` va `logs/<scan>.log`, sau do in summary bang
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

`CveLookupAgent` ho tro ba mode: `mock`, `nvd_live`, va `auto`. O che do
`mock`, agent dung `data/cve_mock_db.json` de demo an toan. O che do
`nvd_live`, agent goi NVD CVE API 2.0, doc `NVD_API_KEY` tu environment, ton
trong rate limit, va luu cache tai `data/cache/nvd/`. O che do `auto`, agent
uu tien NVD live khi co API key va fallback sang cache/mock khi can. Agent
lookup theo service/product/version/CPE va chi giu cac match co CVSS tu `7.0`
tro len.

`NucleiAgent` ho tro ba mode: `mock`, `cli`, va `auto`. O che do `mock`, agent
doc fixture web-template tu `data/nuclei_mock_db.json` de demo on dinh. O che
do `cli`, agent goi Nuclei OSS local, chi scan URL da qua scope guard, dung
`-list`, `-jsonl`, `-no-interactsh`, loai tru tag
`dos,brute-force,intrusive`, va chi giu severity `critical,high`. O che do
`auto`, agent uu tien Nuclei CLI va fallback sang mock khi binary, template,
timeout hoac loi runtime xay ra. Agent khong dung ProjectDiscovery Cloud API va
khong tu discover target moi.

Pipeline deduplicate finding theo `host`, `port`, `cve_id`, `title` va
`source_type`, dong thoi merge `source_agents` va evidence. Risk score duoc tinh theo
`cvss * 10 * confidence`, cong them `5` khi co Nuclei confirmation va gioi han
toi da `100`. Report Markdown gom Executive Summary, Scope, Findings by
Severity, Technical Details, Remediation va Appendix.

Orchestrator chay cac agent doc lap bang `asyncio.gather` voi semaphore gioi
han boi `scanner.max_concurrency`. Log JSONL ghi `agent_timing.started_at`,
`ended_at` va `duration_seconds` cho tung agent de chung minh cac agent co the
overlap thoi gian chay.

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
