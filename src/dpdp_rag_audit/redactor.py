from __future__ import annotations

import re
from .verhoeff import validate_verhoeff
from .rules.identifiers import (
    AADHAAR_CANDIDATE_RE,
    GSTIN_RE,
    MOBILE_RE,
    PAN_RE,
    UPI_RE,
)


def redact_identifiers(text: str) -> tuple[str, int]:
    """Redacts Indian identifiers from text. Returns (cleaned_text, replacements_count)."""
    if not text:
        return text, 0

    count = 0
    cleaned = text

    # Redact Aadhaar if Verhoeff valid
    def replace_aadhaar(match: re.Match) -> str:
        nonlocal count
        raw = match.group(1)
        digits = re.sub(r"[\s-]", "", raw)
        if len(digits) == 12 and validate_verhoeff(digits):
            count += 1
            return "[REDACTED:AADHAAR]"
        return raw

    cleaned = AADHAAR_CANDIDATE_RE.sub(replace_aadhaar, cleaned)

    # Redact PAN
    def replace_pan(match: re.Match) -> str:
        nonlocal count
        count += 1
        return "[REDACTED:PAN]"

    cleaned = PAN_RE.sub(replace_pan, cleaned)

    # Redact GSTIN
    def replace_gstin(match: re.Match) -> str:
        nonlocal count
        count += 1
        return "[REDACTED:GSTIN]"

    cleaned = GSTIN_RE.sub(replace_gstin, cleaned)

    # Redact Mobile
    def replace_mobile(match: re.Match) -> str:
        nonlocal count
        count += 1
        return "[REDACTED:PHONE]"

    cleaned = MOBILE_RE.sub(replace_mobile, cleaned)

    # Redact UPI
    def replace_upi(match: re.Match) -> str:
        nonlocal count
        count += 1
        return "[REDACTED:UPI]"

    cleaned = UPI_RE.sub(replace_upi, cleaned)

    return cleaned, count
