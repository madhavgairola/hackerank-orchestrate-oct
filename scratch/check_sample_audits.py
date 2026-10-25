import pandas as pd
import json

samples = pd.read_csv("dataset/sample_deletion_requests.csv")
outputs = pd.read_csv("dataset/sample_output.csv")
users = pd.read_csv("dataset/user_identities.csv")

merged = samples.merge(outputs, on="case_id").merge(users, on="email", how="left")
for _, r in merged.iterrows():
    steps = json.loads(r["steps_json"])
    audit_recs = [s["resource_id"] for s in steps if s["resource_id"].startswith("audit_record_")]
    accts = [s["resource_id"] for s in steps if s["resource_id"].startswith("account_")]
    print(f"{r['case_id']}: user={r['user_id']}, email={r['email']}, accts={accts}, audit_recs={audit_recs}")
