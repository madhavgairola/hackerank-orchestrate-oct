import glob
import sqlite3

for p in glob.glob("dataset/evidence/databases/*.sql"):
    con = sqlite3.connect(":memory:")
    with open(p, "r", encoding="utf-8") as f:
        con.executescript(f.read())
    c = con.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [t[0] for t in c.fetchall() if t[0] != "snapshot_scope"]
    for t in tables:
        c.execute(f"SELECT * FROM {t}")
        cols = [d[0] for d in c.description]
        for row in c.fetchall():
            row_str = str(row)
            if "6645" in row_str or "5569" in row_str:
                print(p, t, dict(zip(cols, row)))
    con.close()
