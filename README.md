# Phase 3 Vulnerability Scanning MVP

Project này triển khai **Phase 3 - Vulnerability Scanning** trong quy trình
pentesting một mục tiêu đã được cho phép. Pipeline nhận artifact `enum.json`
từ giai đoạn enumeration trước đó, chạy các agent kiểm tra lỗ hổng, chuẩn hóa
và hợp nhất kết quả, xếp hạng rủi ro, sau đó tạo `vuln.json` và báo cáo
Markdown.

Project chỉ thực hiện vulnerability assessment. Project không tự thực hiện
reconnaissance, không mở rộng phạm vi mục tiêu và không khai thác lỗ hổng.

## Mục tiêu

- Nhận dữ liệu enumeration có cấu trúc từ `enum.json`.
- Kiểm tra mọi host bằng scope guard trước khi chạy agent.
- Chạy độc lập các agent CVE lookup và Nuclei bằng pipeline bất đồng bộ.
- Chuẩn hóa, deduplicate, merge và xếp hạng vulnerability candidates.
- Lưu kết quả JSON phục vụ triage và tạo báo cáo Markdown dễ kiểm tra.
- Cung cấp chế độ demo an toàn, có thể tái lập bằng sample và mock data.

## Kiến trúc và luồng xử lý

```text
enum.json
   |
   v
Schema validation + ScopeGuard
   |
   +--> cve_lookup_agent
   |
   +--> nuclei_agent
   |
   v
Deduplicate + Merge + Risk scoring
   |
   +--> triage/*.json
   +--> reports/<scan>/vuln.json
   +--> reports/<scan>/report.md
   +--> logs/*.log
```

`Phase3Orchestrator` chạy các agent độc lập bằng `asyncio.gather` và giới hạn
concurrency bằng `asyncio.Semaphore`. Một agent lỗi sẽ trả về trạng thái lỗi
trong `AgentResult` thay vì làm dừng toàn bộ pipeline.

Theo cấu hình hiện tại:

- `cve_lookup_agent` dùng chế độ `auto`: ưu tiên cache hoặc NVD khi được cấu
  hình phù hợp, và có thể dùng mock database để demo an toàn.
- `nuclei_agent` mặc định chạy ở chế độ `mock`; chế độ CLI thật tùy theo
  `config.yaml`, binary Nuclei và môi trường của người chạy.
- Chỉ các CVE đạt ngưỡng CVSS cấu hình và các severity Nuclei được cho phép
  mới được đưa vào kết quả.

## Cấu trúc project

```text
.
|-- .pi/                 # Tài nguyên hỗ trợ workflow Pi của project
|-- app/                 # Source code chính của Phase 3
|   |-- agents/          # CVE lookup agent và Nuclei agent
|   |-- merge/           # Deduplicate, merge và risk scoring
|   |-- normalizers/     # Chuẩn hóa enum input
|   |-- reports/         # Sinh báo cáo Markdown
|   |-- schemas/         # Pydantic schemas cho input/output/agent result
|   `-- tools/           # Scope guard và NVD client
|-- data/                # Sample input, Pi input và mock databases
|-- docs/                # Tài liệu bổ sung và tài liệu lưu trữ
|-- logs/                # Log pipeline và trạng thái agent
|-- reports/             # Output theo từng lần chạy và báo cáo Markdown
|-- tests/               # Test suite bằng pytest
|-- triage/              # JSON kết quả mới nhất phục vụ triage/workflow
|-- config.yaml          # Cấu hình scope, concurrency, CVE lookup và Nuclei
|-- requirements.txt     # Python dependencies
`-- run_phase3.py        # CLI entry point
```

Vai trò các thư mục chính:

- `.pi/`: chứa tài nguyên hỗ trợ cho workflow Pi như agent, prompt, skill và
  thiết lập liên quan. Nội dung cụ thể tùy theo cấu hình project.
- `app/`: chứa toàn bộ logic ứng dụng, được tách thành agent, schema, tool,
  normalizer, merge/scoring và report.
- `data/`: chứa input mẫu trong `data/samples/`, input theo workflow Pi trong
  `data/pi/` và mock database dùng cho demo an toàn.
- `reports/`: nên được dùng làm giá trị `--out`; mỗi thư mục scan chứa
  `vuln.json` và `report.md`.
- `triage/`: chứa bản JSON kết quả mới nhất, gồm `vuln.json`,
  `cve_candidates.json` và `nuclei_results.json`.
- `logs/`: chứa log theo lần chạy và `pipeline.log`, bao gồm trạng thái, lỗi
  và timing của agent.
- `tests/`: chứa test cho schema, scope guard, normalizer, agent, NVD client,
  merge, scoring và orchestrator.

## Yêu cầu môi trường

- Windows 10/11
- Python 3.11 trở lên
- PowerShell
- Nuclei chỉ cần thiết khi chủ động cấu hình chạy CLI thật
- Không bắt buộc sử dụng `.venv`

## Cài đặt trên Windows

Project có thể chạy trực tiếp bằng Python hiện tại, không bắt buộc kích hoạt
`.venv`. Tại thư mục gốc của project, kiểm tra Python và cài dependencies:

```powershell
python --version
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest
```

Nên dùng Python 3.11 trở lên. Lệnh `python -m pip` giúp bảo đảm dependencies
được cài cho đúng interpreter đang dùng để chạy project.

Nếu muốn tách môi trường Python, người dùng có thể tự tạo virtual environment,
nhưng project không yêu cầu bắt buộc.

## Cấu hình `.env`

Tạo file `.env` tại thư mục gốc của project khi cần lưu biến môi trường như
`OPENAI_API_KEY` hoặc `NVD_API_KEY`. `.env` là file văn bản chứa biến môi
trường và secret, không phải virtual environment `.venv`. Không commit `.env`
hoặc API key thật lên GitHub.

Ví dụ nội dung:

```dotenv
# Dành cho tích hợp OpenAI nếu project được cấu hình sử dụng.
OPENAI_API_KEY=your_openai_api_key_here

# Dùng khi cần gọi NVD API trong chế độ phù hợp.
NVD_API_KEY=your_nvd_api_key_here
```

Source hiện tại đọc `NVD_API_KEY` cho CVE lookup. `OPENAI_API_KEY` có thể được
lưu trong `.env` cho tích hợp OpenAI tùy theo cấu hình hoặc phần mở rộng, nhưng
pipeline Phase 3 hiện tại không bắt buộc key này. Nếu không có `NVD_API_KEY`,
hành vi CVE lookup phụ thuộc vào `config.yaml`, cache hiện có và mock database
của project.

## Chạy test

Sau khi cài dependencies:

```powershell
python -m pytest
```

Chạy test với output ngắn:

```powershell
python -m pytest -q
```

## Chạy pipeline

Cú pháp chung:

```powershell
python run_phase3.py --enum <duong-dan-enum.json> --out <thu-muc-output>
```

Ví dụ với sample lab cơ bản:

```powershell
python run_phase3.py --enum data/samples/enum_lab.json --out reports/scan-001
```

Ví dụ với sample đầy đủ:

```powershell
python run_phase3.py --enum data/samples/enum_lab_full.json --out reports/scan-001
```

Ví dụ với artifact Metasploitable3 trong local lab:

```powershell
python run_phase3.py --enum data/samples/enum_metasploitable3_ub1404.json --out reports/metasploitable3-demo
```

Ví dụ với input theo workflow Pi:

```powershell
python run_phase3.py --enum data/pi/enum.json --out reports/pi-phase3
```

Có thể chỉ định file cấu hình khác khi cần:

```powershell
python run_phase3.py --enum data/samples/enum_lab.json --out reports/scan-001 --config config.yaml
```

## Input và output

Input `enum.json` phải tuân theo Pydantic schema trong `app/schemas/`. Dữ liệu
có thể gồm host, IP, OS fingerprint, port, protocol, service, product,
version, CPE, URL, vhost, technology, discovered path và API endpoint.

Sau một lần chạy thành công với `--out reports/scan-001`, các artifact chính
gồm:

```text
reports/scan-001/vuln.json       # Finding đã merge và xếp hạng
reports/scan-001/report.md       # Báo cáo Markdown
triage/vuln.json                 # Bản JSON kết quả mới nhất
triage/cve_candidates.json       # Kết quả từ CVE lookup agent
triage/nuclei_results.json       # Kết quả từ Nuclei agent
logs/scan-001.log                # Log của lần chạy
logs/pipeline.log                # Log pipeline mới nhất
```

Theo quy ước hiện tại, JSON phục vụ triage nằm trong `triage/` hoặc vị trí
được cấu hình cho pipeline; báo cáo Markdown nằm trong thư mục `reports/` được
truyền qua `--out`; log thực thi nằm trong `logs/`.

`vuln.json` chứa summary và danh sách finding đã chuẩn hóa. Mỗi finding có
thể bao gồm CVE/template ID, host, port, source agent, source type, CVSS,
confidence, evidence, remediation và risk score.

## Lưu ý an toàn và phạm vi được phép

- Chỉ chạy project trong local lab, CTF hoặc hệ thống có ủy quyền rõ ràng.
- Chỉ sử dụng localhost, private network hoặc authorized scope đã cấu hình.
- Không scan public target hoặc Internet công cộng.
- Không tự thêm target mới từ kết quả phát hiện.
- Không thực hiện exploit.
- Không brute force.
- Không DoS, stress test hoặc resource exhaustion.
- Không tự động chạy intrusive scanner template.
- Luôn kiểm tra `config.yaml` và phạm vi được phê duyệt trước khi chạy.

Người vận hành chịu trách nhiệm xác nhận quyền kiểm thử và phạm vi mục tiêu.
Scope guard là lớp bảo vệ kỹ thuật, không thay thế cho sự cho phép hợp pháp.
