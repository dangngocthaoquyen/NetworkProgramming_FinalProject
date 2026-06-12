# Demo Script

## Recommended Order
1. Giới thiệu `enum.json` sample và scope lab/private.
2. Chạy command pipeline.
3. Mở `vuln.json`.
4. Mở `report.md`.
5. Mở `triage/cve_candidates.json` và `triage/nuclei_results.json`.
6. Mở log có `agent_timing`.

## Commands
```powershell
python run_phase3.py --enum data/samples/enum_lab.json --out reports/demo-enum-lab
python run_phase3.py --enum data/samples/enum_lab_full.json --out reports/demo-full
```

## If Tests Are Available
```powershell
python -m pytest
```

## If Tests Are Missing
Ghi rõ:
- `pytest` chưa được cài trong môi trường hiện tại
- pipeline demo vẫn chạy được hay không
