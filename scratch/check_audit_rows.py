import sqlite3

con = sqlite3.connect(":memory:")
with open("dataset/evidence/databases/customer_data_inventory_20260916.sql", "r", encoding="utf-8") as f:
    con.executescript(f.read())
c = con.cursor()
c.execute("SELECT * FROM security_audit_records")
cols = [d[0] for d in c.description]
for row in c.fetchall():
    print(dict(zip(cols, row)))
con.close()
