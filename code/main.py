"""
Ghost Data Still Exists — Automated Deletion-Audit Agent CLI Runner
HackerRank Orchestrate October 2026
"""

import argparse
import json
import os
import sys
import time
import pandas as pd

# Add current module directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from identity import IdentityGraph
from evidence_store import EvidenceStore
from policy_engine import PolicyEngine


def run_pipeline(
    dataset_dir: str = "dataset",
    requests_path: str = "dataset/deletion_requests.csv",
    output_path: str = "output.csv",
) -> None:
    start_time = time.time()
    print("=" * 60)
    print("  Ghost Data Still Exists — Deletion-Audit Pipeline")
    print("=" * 60)
    print(f"Dataset directory : {dataset_dir}")
    print(f"Requests input    : {requests_path}")
    print(f"Output target     : {output_path}")

    # 1. Initialize identity graph
    print("\n[1/4] Building Identity Graph...")
    users_csv = os.path.join(dataset_dir, "user_identities.csv")
    audit_csv = os.path.join(dataset_dir, "user_audit_log.csv")
    id_graph = IdentityGraph(users_csv, audit_csv)
    print(f"      Resolved {len(id_graph.users)} unique user identities.")

    # 2. Ingest multi-source evidence
    print("\n[2/4] Ingesting & indexing multi-source evidence store...")
    evidence_store = EvidenceStore(dataset_dir, id_graph)
    print(f"      Ingested {len(evidence_store.items)} grounded evidence items.")

    # 3. Initialize policy engine
    print("\n[3/4] Initializing Policy Engine...")
    rules_csv = os.path.join(dataset_dir, "deletion_rules.csv")
    policy_engine = PolicyEngine(rules_csv, id_graph, evidence_store)

    # 4. Process deletion requests
    print("\n[4/4] Evaluating deletion requests...")
    requests_df = pd.read_csv(requests_path)
    total_cases = len(requests_df)
    print(f"      Loaded {total_cases} cases to evaluate.")

    results = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

    for idx, row in requests_df.iterrows():
        req_dict = row.to_dict()
        cid = str(req_dict["case_id"]).strip()
        status, steps = policy_engine.evaluate_request(req_dict)

        status_counts[status] = status_counts.get(status, 0) + 1
        steps_json_str = json.dumps(steps, separators=(",", ":"))

        results.append({
            "case_id": cid,
            "deletion_status": status,
            "steps_json": steps_json_str,
        })

        if (idx + 1) % 50 == 0 or (idx + 1) == total_cases:
            print(f"      Evaluated {idx + 1}/{total_cases} cases...")

    # Sort results by case_id using natural sorting (case_1, case_2, ..., case_550)
    def case_sort_key(cid: str) -> int:
        digits = "".join(filter(str.isdigit, cid))
        return int(digits) if digits else 0

    results.sort(key=lambda r: case_sort_key(r["case_id"]))

    out_df = pd.DataFrame(results, columns=["case_id", "deletion_status", "steps_json"])
    out_df.to_csv(output_path, index=False)

    elapsed = time.time() - start_time
    print("\n" + "=" * 60)
    print(f"Completed audit evaluation for {len(out_df)} cases in {elapsed:.2f}s")
    print(f"Status breakdown: {status_counts}")
    print(f"Output saved to: {output_path}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists Deletion-Audit CLI")
    parser.add_argument("--dataset", default="dataset", help="Path to dataset directory")
    parser.add_argument("--requests", default="dataset/deletion_requests.csv", help="Path to deletion_requests.csv")
    parser.add_argument("--output", default="output.csv", help="Path to write output.csv")
    args = parser.parse_args()

    run_pipeline(
        dataset_dir=args.dataset,
        requests_path=args.requests,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()
