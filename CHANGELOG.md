# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-14

### Added
- **Voter ID (EPIC) Detection:** Added `DPDP-ID-06` rule for detecting Indian Voter IDs with format and checksum validation.
- **Driving License (DL) Detection:** Added `DPDP-ID-07` rule validating MoRTH format against 36 Indian state and union territory codes.
- **Native SQLite / ChromaDB Scanner:** Added `scan-db` CLI command to read embeddings and chunk metadata directly from SQLite vector stores (`chroma.sqlite3`).
- **Noisy OCR Test Suite:** Added 15 real-world OCR test cases covering noisy formatting, dotted separators, and multi-credential KYC payloads.

### Changed
- Expanded PAN detection regex (`PAN_RE`) to support hyphenated and spaced OCR outputs (`ABCDE 1234 F`, `ABCDE-1234-F`).
- Enhanced Aadhaar candidate extraction to handle dotted (`2345.6789.0124`) and non-breaking space delimiters.

---

## [0.1.0] - 2026-11-14

### Added
- Initial implementation of DPDP Act 2023 & GDPR compliance scanner for RAG knowledge bases.
- Pure Python Verhoeff algorithm implementation for 12-digit Aadhaar checksum validation.
- Core identifier detection for Aadhaar, PAN, GSTIN, Indian mobile numbers, and UPI handles.
- Consent verification and purpose limitation metadata linters.
- Automated PII redaction engine.
- CLI with `scan` and `redact` commands.
