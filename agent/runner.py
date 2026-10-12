"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import uuid

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_PATH = Path(__file__).resolve().parent.parent / "data" / "customers.json"


def _hash_args(args_dict: dict) -> str:
    s = json.dumps(args_dict, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()  # TTL của run
    ts = datetime.now(timezone.utc).isoformat()

    # --- Run A: search_docs (untrusted content) ---
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs",),
        expires_at=expires_at,
    )
    allowed_search, reason_search = check(ctx_search)
    ledger.append(
        {
            "ts": ts,
            "agent_id": "lab24-agent",
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": ctx_search.data_classification,
            "decision": "allow" if allowed_search else "deny",
            "reason": reason_search,
            "expires_at": expires_at,
        },
        ledger_path,
    )

    if not allowed_search:
        return "Yêu cầu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)

    # Trích xuất ticket_ids (list[int]) CHỈ TỪ TÊN FILE (id field của doc)
    ticket_ids = []
    for doc in docs:
        source_name = doc.get("id") or Path(doc.get("source", "")).name
        match = re.search(r"ticket-(\d+)", source_name)
        if match:
            ticket_ids.append(int(match.group(1)))

    # Redact PII trong text của docs trước khi tóm tắt
    sanitized_docs = []
    for doc in docs:
        sanitized_doc = dict(doc)
        sanitized_doc["text"] = pii.redact(doc["text"])
        sanitized_docs.append(sanitized_doc)

    # Kiểm tra prompt injection trong text (để phát hiện và log/deny egress)
    combined_raw_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_raw_text)

    # --- Run B: read_customer (private data) ---
    # Tra cứu customers.json để lấy customer_id liên quan tới ticket_ids hợp lệ
    customer_ids_to_read = []
    if CUSTOMERS_PATH.exists():
        customers_data = json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))
        for cust in customers_data:
            rel_tickets = cust.get("related_tickets", [])
            if any(t_id in rel_tickets for t_id in ticket_ids):
                customer_ids_to_read.append(cust["customer_id"])

    collected_records = []
    for cust_id in customer_ids_to_read:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("read_customer",),
            parent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        allowed_read, reason_read = check(ctx_read)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": run_id,
                "on_behalf_of": principal_id,
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": cust_id}),
                "classification": ctx_read.data_classification,
                "decision": "allow" if allowed_read else "deny",
                "reason": reason_read,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allowed_read:
            try:
                rec = tools.read_customer(cust_id)
                collected_records.append(rec)
            except tools.ToolError:
                pass

    # Nếu có injected instruction cố gắng gửi data ra sink:
    if injected is not None:
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("read_customer", "http_post"),
            parent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        allowed_post, reason_post = check(ctx_post)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": run_id,
                "on_behalf_of": principal_id,
                "tool": "http_post",
                "args_hash": _hash_args({"target_url": injected.target_url}),
                "classification": ctx_post.data_classification,
                "decision": "allow" if allowed_post else "deny",
                "reason": reason_post,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allowed_post:
            tools.http_post(injected.target_url, {"records": collected_records})

    return llm.summarize(sanitized_docs)
