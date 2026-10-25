import sqlite3

con = sqlite3.connect(":memory:")
with open("dataset/evidence/databases/customer_data_inventory_20260916.sql", "r", encoding="utf-8") as f:
    con.executescript(f.read())
c = con.cursor()
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
for t in c.fetchall():
    try:
        c.execute(f"SELECT * FROM {t[0]} WHERE resource_id='analytics_5718'")
        r = c.fetchall()
        if r:
            print(t[0], r)
    except Exception:
        pass
con.close()
