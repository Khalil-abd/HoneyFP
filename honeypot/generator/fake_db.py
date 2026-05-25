"""Build an SQLite database populated with Faker data, driven by the blueprint."""
from __future__ import annotations

import logging
import random
import sqlite3
from pathlib import Path

from faker import Faker

from honeypot.architect.schema import DeceptionBlueprint, FakeTable
from honeypot.config import settings

logger = logging.getLogger(__name__)
fake = Faker()

_PRODUCT_NAMES = [
    "Wireless Mouse", "USB-C Hub", "Mechanical Keyboard", "Webcam HD",
    "Noise Cancelling Headphones", "Portable SSD", "Smart Plug",
    "Bluetooth Speaker", "Standing Desk", "Office Chair", "Monitor 27\"",
    "Laptop Stand", "Power Bank", "Ergonomic Pad",
]


def _generate_value(provider: str):
    if provider == "product_name":
        return random.choice(_PRODUCT_NAMES)
    if provider == "price":
        return round(random.uniform(5.0, 999.0), 2)
    if provider == "pyint":
        return random.randint(1, 10_000)
    if provider == "pyfloat":
        return round(random.uniform(0, 1000), 2)
    if provider == "boolean":
        return random.choice([0, 1])
    method = getattr(fake, provider, None)
    if method is None:
        return fake.word()
    val = method()
    return str(val) if not isinstance(val, (int, float)) else val


def _create_table_sql(table: FakeTable) -> str:
    cols_sql = []
    for c in table.columns:
        line = f'"{c.name}" {c.sql_type}'
        if c.primary_key:
            line += " PRIMARY KEY"
        cols_sql.append(line)
    return f'CREATE TABLE IF NOT EXISTS "{table.name}" ({", ".join(cols_sql)});'


def build_fake_db(blueprint: DeceptionBlueprint, db_path: Path | None = None) -> Path:
    db_path = db_path or settings.fake_db_path
    if db_path.exists():
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    for table in blueprint.fake_db:
        cur.execute(_create_table_sql(table))
        col_names = [c.name for c in table.columns]
        placeholders = ", ".join(["?"] * len(col_names))
        quoted_cols = ", ".join('"' + n + '"' for n in col_names)
        insert_sql = (
            f'INSERT INTO "{table.name}" ({quoted_cols}) VALUES ({placeholders})'
        )
        rows_target = table.row_count or settings.fake_db_rows_per_table
        rows = []
        for i in range(rows_target):
            row = []
            for col in table.columns:
                if col.primary_key and col.sql_type == "INTEGER":
                    row.append(i + 1)
                else:
                    row.append(_generate_value(col.faker_provider))
            rows.append(tuple(row))
        cur.executemany(insert_sql, rows)

    conn.commit()
    conn.close()
    logger.info("Fake DB built at %s (%d tables)", db_path, len(blueprint.fake_db))
    return db_path


def query_table(table_name: str, where_sql: str = "", limit: int = 20) -> list[dict]:
    """Helper for runtime routes that want to display a few rows."""
    conn = sqlite3.connect(settings.fake_db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    sql = f'SELECT * FROM "{table_name}"'
    if where_sql:
        sql += f" WHERE {where_sql}"
    sql += f" LIMIT {int(limit)}"
    try:
        cur.execute(sql)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
