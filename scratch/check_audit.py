import glob
import sqlite3

for p in glob.glob("dataset/evidence/databases/*.sql"):
    con = sqlite3.connect(":memory:")
    with open(p, "r", encoding="utf-8") as f:
        con.executescript(f.read())
    c = con.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [t[0] for t in c.fetchall()]
    for t in tables:
        if "audit" in t or "security" in t:
            c.execute(f"SELECT count(*) FROM {t}")
            cnt = c.fetchone()[0]
            print(p, t, cnt)
    con.close()
