# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa. Trong vòng lặp baseline, agent hoàn toàn chưa có `agent_id`, `run_id` hay danh tính người dùng (`principal_id` / on-behalf-of) để kiểm soát và phân quyền.
- Dẫn chứng: `agent/loop.py:27` (hàm `_naive_loop(message: str, llm)` chỉ nhận câu hỏi `message` và đối tượng `llm`, không khởi tạo hay quản lý định danh nào).

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có policy hay cổng kiểm quyền (PEP) nào kiểm tra mục đích, quyền hạn hay loại dữ liệu trước khi gửi. Thực thể thực sự quyết định việc gửi là kẻ tấn công thông qua chỉ thị prompt injection cài trong ticket (agent coi dữ liệu untrusted như mệnh lệnh). Phía `tools.http_post` chỉ có allowlist kỹ thuật giới hạn URL về `127.0.0.1:10024` để tránh gửi ra ngoài Internet thật, không phải policy kiểm soát truy cập.
- Dẫn chứng: `agent/loop.py:34-44` (trong `_naive_loop`, agent tự động parse `find_injection` và gọi `tools.read_customer` ở dòng 39 rồi gọi thẳng `tools.http_post` ở dòng 44) và `agent/tools.py:68-85` (hàm `http_post`).

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
- Dòng tạo body POST chứa dữ liệu PII khách hàng: `agent/loop.py:44` (truyền `{"records": collected}` vào `tools.http_post`, trong đó `collected` gom các bản ghi hồ sơ riêng từ `tools.read_customer` ở dòng 39).
- Bằng chứng sink đã nhận body đó được ghi lại tại file `reports/sink.log` (được ghi nhận bởi server sink trong `sink/sink.py:46-47` thuộc hàm `make_handler`, ghi lại mỗi request POST dưới dạng JSON gồm `path` và `body`).
