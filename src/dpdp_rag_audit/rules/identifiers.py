from __future__ import annotations

import re
from .base import PrivacyViolation, Severity
from ..verhoeff import validate_verhoeff

# Regex patterns for Indian Identifiers under DPDP Act
PAN_RE = re.compile(r"\b([A-Z]{5}[0-9]{4}[A-Z])\b")
GSTIN_RE = re.compile(r"\b([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z])\b")
MOBILE_RE = re.compile(r"(?:\+91[\s-]?)?\b([6-9]\d{9})\b")
UPI_RE = re.compile(r"\b([a-zA-Z0-9.\-_]{2,64}@(?!example\.com|domain\.com|test\.com)[a-zA-Z]{2,32})\b")
PASSPORT_RE = re.compile(r"\b([A-Z][1-9][0-9]{6})\b")
# 12-digit Aadhaar candidate pattern (contiguous or 4-4-4 grouped)
AADHAAR_CANDIDATE_RE = re.compile(r"\b([2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b")


def scan_identifiers(text: str) -> list[PrivacyViolation]:
    violations: list[PrivacyViolation] = []
    if not text:
        return violations

    # 1. Aadhaar Number (Verhoeff checksum validated)
    for m in AADHAAR_CANDIDATE_RE.finditer(text):
        raw = m.group(1)
        digits_only = re.sub(r"[\s-]", "", raw)
        if len(digits_only) == 12 and validate_verhoeff(digits_only):
            masked = f"{digits_only[:4]} XXXX {digits_only[8:]}"
            violations.append(
                PrivacyViolation(
                    rule_id="DPDP-ID-01",
                    law_reference="DPDP Act 2023 Sec 4 & UIDAI Aadhaar Act Sec 29",
                    identifier_type="Aadhaar Number",
                    severity=Severity.CRITICAL,
                    matched_value=masked,
                    char_span=(m.start(), m.end()),
                    description="Unredacted, checksum-valid 12-digit Aadhaar number found in document chunk.",
                    remediation="Mask the first 8 digits or replace with [REDACTED:AADHAAR] prior to vector indexing.",
                )
            )

    # 2. Permanent Account Number (PAN)
    for m in PAN_RE.finditer(text):
        pan = m.group(1)
        violations.append(
            PrivacyViolation(
                rule_id="DPDP-ID-02",
                law_reference="DPDP Act 2023 Sec 4 (Data Minimization)",
                identifier_type="PAN Number",
                severity=Severity.HIGH,
                matched_value=f"{pan[:2]}XXX{pan[-2:]}",
                char_span=(m.start(), m.end()),
                description="Indian Permanent Account Number (PAN) detected in un-anonymized form.",
                remediation="Redact or tokenize PAN identifiers to prevent financial profiling.",
            )
        )

    # 3. Goods & Services Tax Identification Number (GSTIN)
    for m in GSTIN_RE.finditer(text):
        gstin = m.group(1)
        violations.append(
            PrivacyViolation(
                rule_id="DPDP-ID-03",
                law_reference="DPDP Act 2023 Sec 4 & GST Act",
                identifier_type="GSTIN",
                severity=Severity.HIGH,
                matched_value=f"{gstin[:4]}XXXX{gstin[-3:]}",
                char_span=(m.start(), m.end()),
                description="Commercial GSTIN entity identifier present in public knowledge base chunk.",
                remediation="Redact commercial entity identifiers from shared vector indexes.",
            )
        )

    # 4. Indian Mobile Phone Number
    for m in MOBILE_RE.finditer(text):
        phone = m.group(1)
        violations.append(
            PrivacyViolation(
                rule_id="DPDP-ID-04",
                law_reference="DPDP Act 2023 Sec 4 & 6",
                identifier_type="Indian Mobile Number",
                severity=Severity.MEDIUM,
                matched_value=f"{phone[:2]}XXXXXX{phone[-2:]}",
                char_span=(m.start(), m.end()),
                description="Indian 10-digit mobile number found in document.",
                remediation="Anonymize personal contact details unless explicit consent for AI retrieval is recorded.",
            )
        )

    # 5. UPI Virtual Payment Address (VPA)
    for m in UPI_RE.finditer(text):
        upi = m.group(1)
        violations.append(
            PrivacyViolation(
                rule_id="DPDP-ID-05",
                law_reference="DPDP Act 2023 Sec 4 (Financial Data Protection)",
                identifier_type="UPI Handle",
                severity=Severity.MEDIUM,
                matched_value=upi,
                char_span=(m.start(), m.end()),
                description="UPI financial handle detected in document text.",
                remediation="Redact payment addresses to prevent correlation with financial accounts.",
            )
        )

    return violations
