# Contributing to dpdp-rag-audit

Thank you for your interest in contributing to `dpdp-rag-audit`! 

We welcome contributions to expand Indian identifier support, improve detection precision on noisy OCR text, and add vector store integrations.

---

## Development Setup

`dpdp-rag-audit` is designed with **zero external dependencies** in its core runtime (Pure Python 3.9+).

```bash
git clone https://github.com/ashishdhillon/dpdp-rag-audit.git
cd dpdp-rag-audit
pip install -e .
```

### Running Tests

Run the test suite using standard library `unittest`:

```bash
python -m unittest discover -s tests -v
```

---

## Adding a New Identifier Rule

1. Add the regex or algorithmic validator in `src/dpdp_rag_audit/rules/identifiers.py`.
2. Ensure you check for valid format/checksum to keep the False Positive Rate (FPR) minimal.
3. Assign a rule ID following the `DPDP-ID-XX` convention and reference the relevant statutory clause (e.g. DPDP Act 2023 Sec 4).
4. Update `src/dpdp_rag_audit/redactor.py` with masking logic.
5. Add test cases in `tests/test_dpdp.py` and `tests/test_ocr_dataset.py`.

---

## Guidelines

- Keep the core package dependency-free.
- Make small, focused commits with conventional commit messages (`feat:`, `fix:`, `test:`, `docs:`).
- Always verify that all existing tests pass before submitting a pull request.
