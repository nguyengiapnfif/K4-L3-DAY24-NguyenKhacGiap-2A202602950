# Compliance mapping — CP5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 | Che PII trước khi đi tiếp giữa các run; phân loại dữ liệu `restricted`; audit ledger; chặn egress dữ liệu restricted | `agent/pii.py:46` (detect), `agent/pii.py:86` (redact), `agent/runner.py:139` (redact trước summary), `agent/policy.py:73-74` (restricted+egress deny), `agent/ledger.py:48` | Điều khoản cụ thể: **chưa xác minh** (chưa đọc văn bản gốc trên cổng văn bản pháp luật chính thức). Dữ liệu giả; không phải chứng nhận tuân thủ. |
| NĐ 356/2025/NĐ-CP | Mục đích xử lý gắn principal (`purposes` trong `data/principals.json`), kiểm purpose + TTL, ledger có `on_behalf_of`, `reason` | `agent/policy.py:93-100` (TTL, purpose), `agent/runner.py:106-121` (ledger Run A), `agent/runner.py:171-185` (ledger read_customer) | Điều khoản cụ thể: **chưa xác minh**. Không có cơ chế đồng ý, quyền của chủ thể dữ liệu hay xoá dữ liệu. |
| Luật AI 134/2025/QH15 | Truy vết hành vi agent: mỗi tool call allow/deny đều ghi ledger hash chain, có `agent_id`, `run_id` | `agent/ledger.py:48`, `agent/ledger.py:74` (verify), `agent/runner.py:209-223` (deny http_post) | Điều khoản cụ thể: **chưa xác minh**. Hash chain không chống cắt đuôi; agent chỉ là mock. |
| OWASP ASI01 (chiếm quyền mục tiêu agent qua nội dung không tin cậy)* | Run A đọc ticket nhưng không chạm private store/egress; ID chỉ lấy từ tên file; lure không điều khiển được `read_customer` | `agent/runner.py:131` (ID từ tên file), `agent/runner.py:146-155` (Run B tra `related_tickets`), `tests/test_split.py`, `tests/test_injection.py` | Mock bắt chỉ thị bằng marker; biện pháp chính là kiến trúc (containment), không phải bộ lọc chuỗi. |
| OWASP ASI03 (lạm dụng quyền/danh tính)* | OBO: quyền hiệu lực = `allowed_tools` ∩ `agent_scopes` ∩ `parent_scopes`; fail-closed khi thiếu principal/scope/TTL | `agent/policy.py:77-108`, `data/principals.json`, `tests/test_obo.py` | `--as` chỉ chọn fixture, không phải xác thực thật. |
| OWASP ASI04 (chuỗi cung ứng)* | Hash-lock dependency; hook Gitleaks pin v8.30.1; quét lịch sử tìm token giả | `requirements.lock`, `.pre-commit-config.yaml`, `reports/secrets-incident.md`, `tests/test_supply_chain.py` | Không kiểm MCP/tool rug pull; lock không thay thế việc rotate secret. |

\* Tên và mã ASI01/03/04 được gán theo chủ đề, **chưa đối chiếu** với bản OWASP Agentic Security hiện hành (nguồn cần kiểm: genai.owasp.org).

Bảng này không phải chứng nhận tuân thủ. Số dòng đã kiểm tại thời điểm viết; kiểm lại nếu sửa code.
