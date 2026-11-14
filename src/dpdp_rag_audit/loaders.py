from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Tuple


def scan_sqlite_vector_store(
    db_path: Path | str,
    table_name: str | None = None,
    text_column: str = "document",
    metadata_column: str = "metadata",
) -> List[Tuple[str, Dict[str, Any] | None]]:
    """Reads document chunks and metadata records directly from SQLite vector stores (e.g. ChromaDB)."""
    p = Path(db_path)
    if not p.is_file():
        raise FileNotFoundError(f"Database file not found: {db_path}")

    conn = sqlite3.connect(str(p))
    cursor = conn.cursor()

    items: List[Tuple[str, Dict[str, Any] | None]] = []

    try:
        # Detect ChromaDB schema if table not explicitly provided
        if table_name is None:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            if "embeddings" in tables:
                table_name = "embeddings"
                text_column = "document"
            elif "documents" in tables:
                table_name = "documents"
                text_column = "text"
            elif tables:
                table_name = tables[0]
            else:
                return items

        # Check table columns
        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = [row[1] for row in cursor.fetchall()]

        has_text = text_column in columns
        has_meta = metadata_column in columns

        if not has_text:
            # Fall back to first text-like column
            text_candidates = [c for c in columns if any(kw in c.lower() for kw in ("doc", "text", "chunk", "content"))]
            if text_candidates:
                text_column = text_candidates[0]
            elif columns:
                text_column = columns[0]

        query = f"SELECT {text_column}" + (f", {metadata_column}" if has_meta else "") + f" FROM {table_name}"
        cursor.execute(query)

        for row in cursor.fetchall():
            doc_text = str(row[0]) if row[0] is not None else ""
            meta_dict = None
            if has_meta and len(row) > 1 and row[1]:
                raw_meta = row[1]
                if isinstance(raw_meta, str):
                    try:
                        meta_dict = json.loads(raw_meta)
                    except Exception:
                        meta_dict = {"raw_metadata": raw_meta}
                elif isinstance(raw_meta, dict):
                    meta_dict = raw_meta

            items.append((doc_text, meta_dict))

    finally:
        conn.close()

    return items
