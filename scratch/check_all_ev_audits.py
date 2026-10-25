import sys
sys.path.insert(0, "code")
import re
import os
import pandas as pd
from identity import IdentityGraph

idg = IdentityGraph("dataset/user_identities.csv", "dataset/user_audit_log.csv")

ev_store_audits = []
for root, dirs, files in os.walk("dataset/evidence"):
    for f in files:
        p = os.path.join(root, f)
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                txt = fh.read()
                matches = set(re.findall(r'audit_record_\d+', txt))
                for m in matches:
                    ev_store_audits.append((m, f))
        except Exception:
            pass

print("Total audit_record_ occurrences in evidence:", len(ev_store_audits))
unique_audits = sorted(list(set([a[0] for a in ev_store_audits])))
print("Unique audit_records:", len(unique_audits))
