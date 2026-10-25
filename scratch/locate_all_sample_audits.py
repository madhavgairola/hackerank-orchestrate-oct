import glob
import os
import pandas as pd
import json

outputs = pd.read_csv("dataset/sample_output.csv")
targets = {}
for _, r in outputs.iterrows():
    steps = json.loads(r["steps_json"])
    for s in steps:
        if s["resource_id"].startswith("audit_record_"):
            targets[s["resource_id"]] = r["case_id"]

print("Target audit records to locate:", len(targets))

results = {k: [] for k in targets}
for root, dirs, files in os.walk("dataset"):
    for f in files:
        if f == "sample_output.csv":
            continue
        p = os.path.join(root, f)
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                txt = fh.read()
                for t in targets:
                    if t in txt:
                        results[t].append(p)
        except Exception:
            pass

for k, files in results.items():
    print(k, f"(from {targets[k]}):", files)
