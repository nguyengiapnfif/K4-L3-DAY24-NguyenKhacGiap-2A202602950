"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Regex patterns
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_CCCD = re.compile(r"\b\d{12}\b")
# Phone in Vietnam: starts with 0 and followed by 9 digits (total 10 digits) or with separators
RE_PHONE = re.compile(r"(?<!\d)(0\d{9})(?!\d)")
# Bank account: 8-16 digits often preceded by STK / số tài khoản / TK
RE_BANK_ACCOUNT = re.compile(
    r"(?i)(?:STK|số\s+tài\s+khoản|tài\s+khoản|TK)\s*[:#\-]?\s*(\d{8,16})\b"
)


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    # 1. EMAIL
    for m in RE_EMAIL.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. BANK ACCOUNT (prioritize capture group of the account number)
    for m in RE_BANK_ACCOUNT.finditer(text):
        start, end = m.start(1), m.end(1)
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    # 3. CCCD (12 digits) - avoid if overlapping with already found bank accounts
    for m in RE_CCCD.finditer(text):
        start, end = m.start(), m.end()
        # check if already captured
        overlap = False
        for e in entities:
            if start < e["end"] and end > e["start"]:
                overlap = True
                break
        if not overlap:
            entities.append({"type": "VN_CCCD", "start": start, "end": end})

    # 4. PHONE (10 digits starting with 0) - avoid if overlapping with CCCD / Bank account
    for m in RE_PHONE.finditer(text):
        start, end = m.start(1), m.end(1)
        overlap = False
        for e in entities:
            if start < e["end"] and end > e["start"]:
                overlap = True
                break
        if not overlap:
            entities.append({"type": "VN_PHONE", "start": start, "end": end})

    # Sort entities by start offset ascending
    entities.sort(key=lambda x: (x["start"], x["end"]))
    return entities


def redact(text: str) -> str:
    entities = detect(text)
    if not entities:
        return text

    # Sort by start descending to replace without offsetting indices
    sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
    res = text
    for e in sorted_entities:
        placeholder = f"[REDACTED_{e['type']}]"
        res = res[: e["start"]] + placeholder + res[e["end"] :]
    return res
