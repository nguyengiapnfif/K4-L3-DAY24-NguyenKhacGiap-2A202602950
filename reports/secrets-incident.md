# Secret giả trong lịch sử Git — CP4

> Token trong bài lab là **giả và đã vô hiệu** (`LAB24-DEMO-...`), do repo đề bài cố ý cài để luyện phát hiện/ứng phó. Không phải credential thật.

- **Scanner và phiên bản:** Gitleaks v8.30.1 (`gitleaks version` → `8.30.1`, bản release chính thức `gitleaks_8.30.1_windows_x64.zip`), cấu hình `.gitleaks.toml` (`useDefault = true` + rule riêng của lab). Hook pre-commit: `gitleaks-system`, `rev: v8.30.1`, `pass_filenames: false` (`.pre-commit-config.yaml`).
- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`, "chore: seed student lab with synthetic secret exercise", tác giả VinUni AI20k Lab).
- **File, rule và kết quả quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact .` → `10 commits scanned`, `leaks found: 1`, **exit code 1** (kết quả mong đợi). Finding: `RuleID: lab24-synthetic-token`, `File: lab-fake-secret.txt`, `Line: 1`, commit `1bdd849`. Giá trị token được che bằng `--redact`.
- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` → `no leaks found`, **exit code 0**. File `lab-fake-secret.txt` đã bị xoá ở commit sau; không cần allowlist cho `.venv/` vì không có false positive nào xuất hiện trên máy này, và không tắt/nới rule nào.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. Coi token là đã lộ: **thu hồi/rotate** ngay tại dịch vụ cấp token, cấp token mới và cập nhật nơi dùng hợp lệ.
  2. Rà log truy cập của dịch vụ để tìm việc sử dụng trái phép từ thời điểm commit `1bdd849` đến khi rotate.
  3. Xử lý các bản sao: fork, clone, CI cache, artifact. Có thể viết lại lịch sử (git filter-repo/BFG) và force-push, nhưng đó chỉ là dọn dẹp, không thay thế rotate.
  4. Ghi lại sự cố (ai, khi nào, phạm vi, đã rotate lúc nào) và thêm hook quét trước commit.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** token vẫn nằm trong lịch sử Git và mọi bản clone/fork; ai có bản sao đó vẫn dùng được cho tới khi **rotate**. Pin dependency + hash lock (`requirements.lock`) chỉ chống supply-chain tampering của gói cài đặt; pre-commit hook chỉ ngăn secret mới đi vào commit, không gỡ secret đã lộ.
