import os
import sys
import json
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "code")))
from identity import IdentityGraph
from evidence_store import EvidenceStore
from policy_engine import PolicyEngine

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
dataset_dir = os.path.join(repo_root, "dataset")
identities_csv = os.path.join(dataset_dir, "user_identities.csv")
audit_csv = os.path.join(dataset_dir, "user_audit_log.csv")

graph = IdentityGraph(identities_csv, audit_csv)
store = EvidenceStore(dataset_dir, graph)
engine = PolicyEngine(dataset_dir, graph, store)

samples_df = pd.read_csv(os.path.join(dataset_dir, "sample_deletion_requests.csv"))
results = []

for _, r in samples_df.iterrows():
    status, steps = engine.evaluate_request(r.to_dict())
    results.append({
        "case_id": r["case_id"],
        "deletion_status": status,
        "steps_json": json.dumps(steps)
    })

out_df = pd.DataFrame(results)
out_path = os.path.join(repo_root, "code", "tests", "sample_predictions_v2.csv")
out_df.to_csv(out_path, index=False)
print(f"Generated {len(out_df)} predictions to {out_path}")
