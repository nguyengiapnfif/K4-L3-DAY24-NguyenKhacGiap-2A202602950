"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict[str, dict]:
    if not PRINCIPALS_PATH.exists():
        return {}
    with PRINCIPALS_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def check(context: PolicyContext) -> tuple[bool, str]:
    # 1. Kiểm tra data_classification hợp lệ
    valid_classifications = {"public", "internal", "restricted"}
    if context.data_classification not in valid_classifications:
        return False, f"Invalid data_classification: {context.data_classification}"

    # 2. Rule tối thiểu: data restricted + egress -> DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Egress is prohibited when accessing restricted data classification"

    # 3. Kiểm tra principal & OBO
    if context.principal_id:
        principals = _load_principals()
        if context.principal_id not in principals:
            return False, f"Unknown principal_id: {context.principal_id}"

        principal_info = principals[context.principal_id]

        # Kiểm tra expiration
        if context.expires_at:
            try:
                exp_dt = datetime.fromisoformat(context.expires_at)
                now_utc = datetime.now(timezone.utc)
                if exp_dt <= now_utc:
                    return False, f"Context has expired at {context.expires_at}"
            except Exception as e:
                return False, f"Invalid expires_at format: {e}"

        # Kiểm tra purpose
        if context.request_purpose:
            allowed_purposes = principal_info.get("purposes", [])
            if context.request_purpose not in allowed_purposes:
                return False, f"Purpose '{context.request_purpose}' is not authorized for principal '{context.principal_id}'"

        # Kiểm tra requested_tool và scopes
        if context.requested_tool:
            principal_allowed_tools = principal_info.get("allowed_tools", [])
            if context.requested_tool not in principal_allowed_tools:
                return False, f"Tool '{context.requested_tool}' is not in allowed_tools for principal '{context.principal_id}'"

            if context.agent_scopes and context.requested_tool not in context.agent_scopes:
                return False, f"Tool '{context.requested_tool}' exceeds agent_scopes"

            if context.delegation_depth > 0:
                if not context.parent_scopes or context.requested_tool not in context.parent_scopes:
                    return False, f"Delegation depth {context.delegation_depth} exceeds parent_scopes for tool '{context.requested_tool}'"

    return True, f"Authorized access for classification={context.data_classification}, tool={context.requested_tool or 'none'}, principal={context.principal_id or 'none'}"
