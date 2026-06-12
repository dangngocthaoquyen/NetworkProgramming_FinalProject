# Source Trace Policy

## Current State
Project hiện có:
- `source_agents`
- `source_type`
- `evidence`
- Agent-specific output files trong `.pi/outputs/`

Đây là trace hữu ích để lần theo finding xuất phát từ agent nào.

## What Not to Claim
- Chưa có trường `source_trace` chuẩn hóa riêng trong schema cuối.
- Không nên nói output hiện đã có provenance model đầy đủ nếu chưa bổ sung trường đó trong code.

## Recommended Communication
Khi thuyết trình hoặc dùng skill này, nói rằng project đã có attribution cơ bản qua `source_agents` và artifact riêng của từng agent, nhưng source tracing còn có thể mở rộng thêm.
