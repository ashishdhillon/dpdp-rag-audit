# dpdp-rag-audit

[![CI](https://github.com/ashishdhillon/dpdp-rag-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/ashishdhillon/dpdp-rag-audit/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)

Automated compliance linter and privacy scanner for RAG knowledge bases and vector stores under **India's Digital Personal Data Protection Act (DPDP Act 2023)** and **GDPR**.

---

## Why DPDP Compliance Matters for RAG

Under India's DPDP Act 2023 (Section 4 & 6) and GDPR (Article 5 & 17), personal data processed in enterprise systems must adhere to strict **purpose limitation**, **data minimization**, and **consent validation**.

Embedding un-sanitized documents containing Indian identifiers into vector databases exposes organizations to substantial non-compliance liability and unauthorized data aggregation.

`dpdp-rag-audit` provides:
1. **Mathematical Checksum Validation:** Validates 12-digit Aadhaar numbers using the Verhoeff algorithm to filter out 90% of random 12-digit false positives.
2. **Indian Identifier Scanning:** Detects PAN, GSTIN, Indian mobile numbers, UPI handles, and Indian passports.
3. **Metadata Governance Linting:** Verifies consent verification and purpose declarations attached to vector chunks.
4. **Automated Redactor:** Masks personal data before document ingestion into vector databases.

---

## Quickstart

```bash
git clone https://github.com/ashishdhillon/dpdp-rag-audit.git
cd dpdp-rag-audit
pip install -e .
```

Scan documents or chunks:

```bash
# Run on built-in demo corpus
dpdp-rag-audit scan --demo

# Scan a directory of RAG documents (.txt, .md, .json)
dpdp-rag-audit scan docs/

# Output structured JSON report
dpdp-rag-audit scan docs/ --format json

# Redact identifiers in a file before indexing
dpdp-rag-audit redact raw_kb.md -o clean_kb.md
```

---

## Sample Audit Output

```
┌────────────────────────────────────────────────────────────┐
│              DPDP & GDPR RAG COMPLIANCE AUDIT              │
├────────────────────────────────────────────────────────────┤
│ Scanned Chunks: 3     Compliant: 1     Violations: 3       │
│ Compliance Status: NON_COMPLIANT                           │
├────────────────────────────────────────────────────────────┤
│ Privacy Deficiencies Identified:                           │
│  1. [CRITICAL] Aadhaar Number       (DPDP-ID-01)           │
│     Found: 2345 XXXX 0124                                  │
│  2. [HIGH] PAN Number               (DPDP-ID-02)           │
│     Found: ABXXX4F                                         │
│  3. [MEDIUM] Indian Mobile Number   (DPDP-ID-04)           │
│     Found: 98XXXXXX10                                      │
└────────────────────────────────────────────────────────────┘
```

---

## Python API Usage

```python
from dpdp_rag_audit import DPDPScanner, redact_identifiers

scanner = DPDPScanner()

chunk = "Candidate Aadhaar: 2345 6789 0124, PAN: ABCDE1234F"
violations = scanner.scan_chunk(chunk)

for v in violations:
    print(f"[{v.severity}] {v.identifier_type}: {v.description}")

# Automatic masking
clean_chunk, count = redact_identifiers(chunk)
print(clean_chunk)
# "Candidate Aadhaar: [REDACTED:AADHAAR], PAN: [REDACTED:PAN]"
```

---

## License

MIT © [Ashish Dhillon](https://github.com/ashishdhillon)
