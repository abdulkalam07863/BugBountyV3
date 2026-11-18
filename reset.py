#!/usr/bin/env python3
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parent / "bh.db"
c = sqlite3.connect(DB)
c.row_factory = sqlite3.Row

NEED = {
    "projects": [("url", "TEXT"), ("slug", "TEXT"), ("name", "TEXT"), ("status", "TEXT"),
                 ("stage", "TEXT"), ("cycle", "INTEGER DEFAULT 0"),
                 ("attempts", "INTEGER DEFAULT 0"), ("escalation", "INTEGER DEFAULT 0"),
                 ("toolchain", "TEXT DEFAULT 'unknown'"),
                 ("type_conf", "TEXT DEFAULT 'unresolved'"),
                 ("type_evidence", "TEXT DEFAULT '{}'"), ("type_locked", "INTEGER DEFAULT 0"),
                 ("max", "INTEGER DEFAULT 0"), ("rank", "INTEGER DEFAULT 50"),
                 ("tvl", "INTEGER DEFAULT 0"), ("details_ok", "INTEGER DEFAULT 0"),
                 ("cond_ok", "INTEGER DEFAULT 0"), ("targets_n", "INTEGER DEFAULT 0"),
                 ("readiness", "INTEGER DEFAULT 0"), ("fund_hits", "INTEGER DEFAULT 0"),
                 ("auto", "INTEGER DEFAULT 1"), ("source", "TEXT DEFAULT 'auto'"),
                 ("manual", "INTEGER DEFAULT 0"), ("notes", "TEXT DEFAULT ''"),
                 ("added", "REAL"), ("updated", "REAL")],
    "findings": [("pid", "INTEGER"), ("title", "TEXT"), ("sev", "TEXT"), ("cls", "TEXT"),
                 ("file", "TEXT"), ("line", "INTEGER"), ("evidence", "TEXT"),
                 ("score", "INTEGER DEFAULT 0"), ("fund", "INTEGER DEFAULT 0"),
                 ("reward", "INTEGER DEFAULT 0"), ("gate", "TEXT DEFAULT ''"),
                 ("blockers", "TEXT DEFAULT '[]'"), ("judged", "INTEGER DEFAULT 0"),
                 ("eligible", "INTEGER DEFAULT 0"), ("poc_path", "TEXT DEFAULT ''"),
                 ("tool", "TEXT"), ("ts", "REAL")],
    "log": [("pid", "INTEGER"), ("ts", "REAL"), ("line", "TEXT")],
    "repairs": [("pid", "INTEGER"), ("kind", "TEXT"), ("detail", "TEXT"), ("ts", "REAL")],
    "rejections": [("url", "TEXT"), ("why", "TEXT"), ("ts", "REAL")],
}

for t, cols in NEED.items():
    c.execute("CREATE TABLE IF NOT EXISTS %s(id INTEGER PRIMARY KEY AUTOINCREMENT)" % t)
    have = {r["name"] for r in c.execute("PRAGMA table_info(%s)" % t)}
    for n, d in cols:
        if n not in have:
            c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (t, n, d))
c.commit()
print("reset ok: %d projects" % c.execute("SELECT COUNT(*) FROM projects").fetchone()[0])