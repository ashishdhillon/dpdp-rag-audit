import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from dpdp_rag_audit.loaders import scan_sqlite_vector_store
from dpdp_rag_audit.scanner import DPDPScanner
from dpdp_rag_audit.cli import main


class TestLoaders(unittest.TestCase):
    def test_sqlite_chroma_loader(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "chroma.sqlite3"
            conn = sqlite3.connect(str(db_file))
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TABLE embeddings (id TEXT, document TEXT, metadata TEXT);"
            )

            valid_aadhaar = "2345 6789 0124"
            cursor.execute(
                "INSERT INTO embeddings VALUES (?, ?, ?);",
                (
                    "id1",
                    f"User KYC with Aadhaar: {valid_aadhaar}",
                    json.dumps({"consent_verified": True, "purpose": "kyc"}),
                ),
            )
            cursor.execute(
                "INSERT INTO embeddings VALUES (?, ?, ?);",
                (
                    "id2",
                    "Clean technical architectural documentation.",
                    json.dumps({"consent_verified": True, "purpose": "docs"}),
                ),
            )
            conn.commit()
            conn.close()

            items = scan_sqlite_vector_store(db_file)
            self.assertEqual(len(items), 2)

            scanner = DPDPScanner()
            report = scanner.scan_corpus(items)
            self.assertEqual(report.total_items_scanned, 2)
            self.assertEqual(report.compliant_items, 1)
            self.assertEqual(len(report.violations), 1)
            self.assertEqual(report.violations[0].identifier_type, "Aadhaar Number")


if __name__ == "__main__":
    unittest.main()
