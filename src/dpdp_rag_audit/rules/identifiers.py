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
VOTER_ID_RE = re.compile(r"\b([A-Z]{3}[-/]?[0-9]{7})\b")
DRIVING_LICENSE_RE = re.compile(r"\b([A-Z]{2}[-\s]?[0-9]{2}[-\s]?(?:19[7-9][0-9]|20[0-2][0-9])[-\s]?[0-9]{7})\b")
# 12-digit Aadhaar candidate pattern (contiguous or 4-4-4 grouped)
AADHAAR_CANDIDATE_RE = re.compile(r"\b([2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b")

VALID_STATE_CODES = {
    "AN", "AP", "AR", "AS", "BR", "CH", "CG", "DN", "DD", "DL",
    "GA", "GJ", "HR", "HP", "JK", "JH", "KA", "KL", "LA", "LD",
    "MP", "MH", "MN", "ML", "MZ", "NL", "OD", "PY", "PB", "RJ",
    "SK", "TN", "TS", "TR", "UP", "UK", "WB"
}


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

    # 6. Voter ID (Electors Photo Identity Card - EPIC)
    for m in VOTER_ID_RE.finditer(text):
        voter_id = m.group(1)
        violations.append(
            PrivacyViolation(
                rule_id="DPDP-ID-06",
                law_reference="DPDP Act 2023 Sec 4 & Representation of the People Act 1951",
                identifier_type="Voter ID (EPIC)",
                severity=Severity.HIGH,
                matched_value=f"{voter_id[:3]}XXXX{voter_id[-2:]}",
                char_span=(m.start(), m.end()),
                description="Indian Voter ID (EPIC) alphanumeric credential detected.",
                remediation="Redact voter identity numbers to prevent political profiling and identity exposure.",
            )
        )

    # 7. Indian Driving License (DL)
    for m in DRIVING_LICENSE_RE.finditer(text):
        dl_str = m.group(1)
        state_code = dl_str[:2].upper()
        if state_code in VALID_STATE_CODES:
            violations.append(
                PrivacyViolation(
                    rule_id="DPDP-ID-07",
                    law_reference="DPDP Act 2023 Sec 4 & Motor Vehicles Act 1988",
                    identifier_type="Driving License",
                    severity=Severity.HIGH,
                    matched_value=f"{state_code}XXXXXXXX{dl_str[-4:]}",
                    char_span=(m.start(), m.end()),
                    description=f"Indian Driving License with state code '{state_code}' found in document.",
                    remediation="Redact driving license identifiers before vector database insertion.",
                )
            )

    return violations
