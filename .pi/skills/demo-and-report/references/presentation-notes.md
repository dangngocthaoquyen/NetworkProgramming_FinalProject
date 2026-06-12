# Presentation Notes

## Strong Talking Points
- Pipeline đúng Phase 3: nhận `enum.json` từ phase trước.
- Có multi-agent design.
- Có async orchestration và parallel execution ở mức agent-level.
- Có merge, dedup, rank, report.
- Có safety guard chặn public Internet.

## Honest Caveat
- CVE lookup hiện là offline mock DB.
- Nuclei mặc định ở offline-safe/mock hoặc disabled.
- Giá trị chính hiện tại nằm ở orchestration, schema discipline, artifact flow, và demo reproducibility trong lab.

## Do Not Say
- Không nói project đang pentest public Internet.
- Không nói đã query live NVD/OSV nếu chưa thực sự làm.
- Không nói đã có cross-agent semantic correlation mạnh nếu code chưa hỗ trợ.
