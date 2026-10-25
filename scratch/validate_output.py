import csv
import json
import os
import pandas as pd

def validate():
    print("=" * 60)
    print("  Validating output.csv against Project Contract")
    print("=" * 60)

    output_path = "output.csv"
    if not os.path.exists(output_path):
        print("FAIL: output.csv does not exist!")
        return False

    with open(output_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)

    expected_header = ["case_id", "deletion_status", "steps_json"]
    if header != expected_header:
        print(f"FAIL: Header mismatch! Expected {expected_header}, got {header}")
        return False
    print("PASS: Header matches exact columns in order.")

    df = pd.read_csv(output_path)
    if len(df) != 518:
        print(f"FAIL: Row count mismatch! Expected 518, got {len(df)}")
        return False
    print("PASS: Exactly 518 data rows produced.")

    reqs_df = pd.read_csv("dataset/deletion_requests.csv")
    expected_case_ids = reqs_df["case_id"].tolist()
    actual_case_ids = df["case_id"].tolist()

    if set(actual_case_ids) != set(expected_case_ids):
        print("FAIL: Set of case_ids does not match deletion_requests.csv!")
        return False
    print("PASS: Exactly matches all 518 case_ids from dataset/deletion_requests.csv.")

    # Check case sorting
    def case_sort_key(cid: str) -> int:
        digits = "".join(filter(str.isdigit, cid))
        return int(digits) if digits else 0

    sorted_case_ids = sorted(actual_case_ids, key=case_sort_key)
    if actual_case_ids != sorted_case_ids:
        print("FAIL: case_ids are not properly sorted!")
        return False
    print("PASS: Rows properly sorted by case_id.")

    manifest_df = pd.read_csv("dataset/evidence_files.csv")
    file_capture = dict(zip(manifest_df["file_id"], manifest_df["captured_at"]))
    req_audit_ats = dict(zip(reqs_df["case_id"], reqs_df["audit_at"]))

    allowed_finding_ops = {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
    }
    allowed_remed_ops = {
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    }
    allowed_verif_ops = {
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    }
    allowed_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

    required_fields = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]

    cutoff_violations = 0
    formatting_errors = 0
    status_errors = 0

    for idx, row in df.iterrows():
        cid = row["case_id"]
        status = row["deletion_status"]
        steps_raw = row["steps_json"]
        audit_at = req_audit_ats[cid]

        if status not in allowed_statuses:
            print(f"Error in {cid}: invalid status {status}")
            status_errors += 1
            continue

        try:
            steps = json.loads(steps_raw)
        except Exception as e:
            print(f"Error in {cid}: steps_json is not valid JSON: {e}")
            formatting_errors += 1
            continue

        if not isinstance(steps, list):
            print(f"Error in {cid}: steps_json is not an array")
            formatting_errors += 1
            continue

        if status == "NOT_APPLICABLE":
            if len(steps) != 0:
                print(f"Error in {cid}: NOT_APPLICABLE must have empty steps_json, got {len(steps)} steps")
                formatting_errors += 1
            continue

        if status == "COMPLETE":
            # Must only have VERIFICATION steps
            for s in steps:
                if s.get("phase") != "VERIFICATION":
                    print(f"Error in {cid}: COMPLETE case has non-verification step: {s}")
                    formatting_errors += 1
                if not s.get("evidence_id"):
                    print(f"Error in {cid}: COMPLETE case verification step has empty evidence_id: {s}")
                    formatting_errors += 1

        # Check consecutive numbering
        for step_idx, s in enumerate(steps, 1):
            if s.get("step_no") != step_idx:
                print(f"Error in {cid}: step_no mismatch: expected {step_idx}, got {s.get('step_no')}")
                formatting_errors += 1

            for rf in required_fields:
                if rf not in s:
                    print(f"Error in {cid}: missing field {rf} in step {s}")
                    formatting_errors += 1

            phase = s.get("phase")
            op = s.get("operation")
            st = s.get("state")
            ev_id = s.get("evidence_id", "")

            if phase == "FINDING":
                if op not in allowed_finding_ops or st != allowed_finding_ops[op]:
                    print(f"Error in {cid}: invalid finding op/state: {op}/{st}")
                    formatting_errors += 1
                if not ev_id:
                    print(f"Error in {cid}: finding missing evidence_id: {s}")
                    formatting_errors += 1
            elif phase == "REMEDIATION":
                if op not in allowed_remed_ops or st != allowed_remed_ops[op]:
                    print(f"Error in {cid}: invalid remediation op/state: {op}/{st}")
                    formatting_errors += 1
                if ev_id != "":
                    print(f"Error in {cid}: remediation has non-empty evidence_id: {ev_id}")
                    formatting_errors += 1
            elif phase == "VERIFICATION":
                if op not in allowed_verif_ops or st != allowed_verif_ops[op]:
                    print(f"Error in {cid}: invalid verification op/state: {op}/{st}")
                    formatting_errors += 1
                if status == "INCOMPLETE" and ev_id != "":
                    print(f"Error in {cid}: incomplete case verification has non-empty evidence_id: {ev_id}")
                    formatting_errors += 1

            # Check evidence cutoff
            if ev_id and ev_id in file_capture:
                if file_capture[ev_id] > audit_at:
                    print(f"Cutoff violation in {cid}: evidence {ev_id} captured at {file_capture[ev_id]} > audit_at {audit_at}")
                    cutoff_violations += 1

        # Check phase ordering: FINDING -> REMEDIATION -> VERIFICATION
        phase_order = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
        for i in range(len(steps) - 1):
            p1 = phase_order.get(steps[i].get("phase"), 99)
            p2 = phase_order.get(steps[i+1].get("phase"), 99)
            if p1 > p2:
                print(f"Error in {cid}: phase ordering violated: {steps[i]['phase']} before {steps[i+1]['phase']}")
                formatting_errors += 1

    print(f"Validation summary:")
    print(f"  Formatting errors : {formatting_errors}")
    print(f"  Status errors     : {status_errors}")
    print(f"  Cutoff violations : {cutoff_violations}")

    if formatting_errors == 0 and status_errors == 0 and cutoff_violations == 0:
        print("\nALL 518 CASES PASSED VALIDATION WITH ZERO ERRORS!")
        return True
    else:
        print("\nVALIDATION FAILED WITH ERRORS.")
        return False

if __name__ == "__main__":
    validate()
