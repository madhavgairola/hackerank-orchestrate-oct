"""
Evaluation Harness for Ghost Data Still Exists.
Computes case-level, step-level, field-level, and sequence-level metrics
comparing prediction CSV against ground-truth CSV.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Tuple
import pandas as pd


REQUIRED_COLUMNS = ["case_id", "deletion_status", "steps_json"]
ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
ALLOWED_PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
ALLOWED_OPERATIONS = {
    # Findings
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
    # Remediation
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
    # Verification
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
}
ALLOWED_STATES = {
    "PRESENT",
    "ACTIVE",
    "DISABLED",
    "BLOCKED",
    "ABSENT",
    "REDACTED",
    "ANONYMIZED",
}


def parse_and_validate_csv(file_path: str) -> Dict[str, Dict[str, Any]]:
    """
    Parses a prediction or ground-truth CSV and validates structure and schema.
    Returns a dictionary mapping case_id to case data.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    df = pd.read_csv(file_path)

    # Validate header
    if list(df.columns) != REQUIRED_COLUMNS:
        raise ValueError(
            f"Invalid columns in {file_path}. Expected {REQUIRED_COLUMNS}, got {list(df.columns)}"
        )

    records = {}
    for idx, row in df.iterrows():
        case_id = str(row["case_id"]).strip()
        status = str(row["deletion_status"]).strip()
        raw_steps = row["steps_json"]

        if status not in ALLOWED_STATUSES:
            raise ValueError(f"Case {case_id}: Invalid status '{status}'")

        # Parse steps_json
        try:
            steps = json.loads(raw_steps) if isinstance(raw_steps, str) else raw_steps
            if not isinstance(steps, list):
                raise ValueError("steps_json must be a JSON array")
        except Exception as e:
            raise ValueError(f"Case {case_id}: Failed to parse steps_json: {e}")

        # Validate step format
        if status == "NOT_APPLICABLE" and len(steps) != 0:
            raise ValueError(f"Case {case_id}: NOT_APPLICABLE must have empty steps_json array")

        for s_idx, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                raise ValueError(f"Case {case_id} step {s_idx}: step must be a JSON object")
            
            # Check step_no consecutive numbering
            step_no = step.get("step_no")
            if step_no != s_idx:
                raise ValueError(
                    f"Case {case_id} step {s_idx}: step_no is {step_no}, expected consecutive {s_idx}"
                )

            phase = step.get("phase")
            if phase not in ALLOWED_PHASES:
                raise ValueError(f"Case {case_id} step {s_idx}: Invalid phase '{phase}'")

            op = step.get("operation")
            if op not in ALLOWED_OPERATIONS:
                raise ValueError(f"Case {case_id} step {s_idx}: Invalid operation '{op}'")

            state = step.get("state")
            if state not in ALLOWED_STATES:
                raise ValueError(f"Case {case_id} step {s_idx}: Invalid state '{state}'")

            # Check evidence_id rules
            ev_id = str(step.get("evidence_id", "")).strip()
            if status == "INCOMPLETE" and phase in ("REMEDIATION", "VERIFICATION"):
                if ev_id != "":
                    raise ValueError(
                        f"Case {case_id} step {s_idx}: INCOMPLETE {phase} step must have empty evidence_id"
                    )

        records[case_id] = {
            "case_id": case_id,
            "deletion_status": status,
            "steps": steps,
        }

    return records


def evaluate(
    pred_path: str, truth_path: str
) -> Tuple[Dict[str, Any], str]:
    """
    Evaluates predictions against ground truth.
    Returns a dictionary of metrics and a formatted markdown summary string.
    """
    pred_data = parse_and_validate_csv(pred_path)
    truth_data = parse_and_validate_csv(truth_path)

    common_cases = sorted(list(set(pred_data.keys()) & set(truth_data.keys())))
    if not common_cases:
        raise ValueError("No common case_ids found between prediction and ground truth.")

    total_cases = len(truth_data)
    evaluated_cases = len(common_cases)
    missing_in_pred = len(truth_data) - len(common_cases)
    extra_in_pred = len(pred_data) - len(common_cases)

    status_matches = 0
    step_count_matches = 0
    sequence_matches = 0

    # Field-level statistics
    total_gt_steps = 0
    total_pred_steps = 0
    exact_step_matches = 0  # step matches completely (ignoring step_no)

    field_correct = {
        "phase": 0,
        "system_id": 0,
        "resource_id": 0,
        "operation": 0,
        "state": 0,
        "evidence_id": 0,
    }
    field_total = 0

    status_breakdown = {
        "COMPLETE": {"gt": 0, "pred": 0, "correct": 0},
        "INCOMPLETE": {"gt": 0, "pred": 0, "correct": 0},
        "NOT_APPLICABLE": {"gt": 0, "pred": 0, "correct": 0},
    }

    mismatches = []

    for cid in common_cases:
        p_row = pred_data[cid]
        t_row = truth_data[cid]

        p_status = p_row["deletion_status"]
        t_status = t_row["deletion_status"]

        status_breakdown[t_status]["gt"] += 1
        status_breakdown[p_status]["pred"] += 1

        is_status_correct = p_status == t_status
        if is_status_correct:
            status_matches += 1
            status_breakdown[t_status]["correct"] += 1

        p_steps = p_row["steps"]
        t_steps = t_row["steps"]

        total_pred_steps += len(p_steps)
        total_gt_steps += len(t_steps)

        is_count_correct = len(p_steps) == len(t_steps)
        if is_count_correct:
            step_count_matches += 1

        # Check sequence accuracy (exact ordered match of all steps)
        is_sequence_correct = True
        if not is_status_correct or not is_count_correct:
            is_sequence_correct = False
        else:
            for s1, s2 in zip(p_steps, t_steps):
                for k in ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
                    if str(s1.get(k, "")).strip() != str(s2.get(k, "")).strip():
                        is_sequence_correct = False
                        break
                if not is_sequence_correct:
                    break

        if is_sequence_correct:
            sequence_matches += 1
        else:
            if len(mismatches) < 5:  # Store first few mismatches for debugging
                mismatches.append(
                    f"Case {cid}: Expected status {t_status} with {len(t_steps)} steps; Got status {p_status} with {len(p_steps)} steps."
                )

        # Field-level alignment
        min_len = min(len(p_steps), len(t_steps))
        for i in range(min_len):
            s_pred = p_steps[i]
            s_truth = t_steps[i]
            field_total += 1

            step_all_fields_match = True
            for f in ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
                if str(s_pred.get(f, "")).strip() == str(s_truth.get(f, "")).strip():
                    field_correct[f] += 1
                else:
                    step_all_fields_match = False

            if step_all_fields_match:
                exact_step_matches += 1

    case_status_acc = (status_matches / evaluated_cases) * 100 if evaluated_cases > 0 else 0
    step_count_acc = (step_count_matches / evaluated_cases) * 100 if evaluated_cases > 0 else 0
    seq_acc = (sequence_matches / evaluated_cases) * 100 if evaluated_cases > 0 else 0

    step_precision = (exact_step_matches / total_pred_steps * 100) if total_pred_steps > 0 else 0
    step_recall = (exact_step_matches / total_gt_steps * 100) if total_gt_steps > 0 else 0
    step_f1 = (
        (2 * step_precision * step_recall / (step_precision + step_recall))
        if (step_precision + step_recall) > 0
        else 0
    )

    metrics = {
        "total_ground_truth_cases": total_cases,
        "evaluated_cases": evaluated_cases,
        "missing_in_pred": missing_in_pred,
        "extra_in_pred": extra_in_pred,
        "case_status_accuracy_pct": case_status_acc,
        "step_count_accuracy_pct": step_count_acc,
        "sequence_accuracy_pct": seq_acc,
        "step_precision_pct": step_precision,
        "step_recall_pct": step_recall,
        "step_f1_pct": step_f1,
        "field_accuracies": {
            f: (field_correct[f] / field_total * 100 if field_total > 0 else 0)
            for f in field_correct
        },
        "status_breakdown": status_breakdown,
    }

    # Format output string
    lines = [
        "===========================================================",
        "               DELETION-AUDIT EVALUATION REPORT             ",
        "===========================================================",
        f"Evaluated Cases: {evaluated_cases} / {total_cases} (Missing: {missing_in_pred}, Extra: {extra_in_pred})",
        "",
        "--- High-Level Accuracies ---",
        f"Case-Level Status Accuracy : {case_status_acc:6.2f}% ({status_matches}/{evaluated_cases})",
        f"Step-Count Accuracy        : {step_count_acc:6.2f}% ({step_count_matches}/{evaluated_cases})",
        f"Full Sequence Accuracy     : {seq_acc:6.2f}% ({sequence_matches}/{evaluated_cases})",
        "",
        "--- Step-Level Accuracy (Exact Step Match) ---",
        f"Predicted Steps            : {total_pred_steps}",
        f"Ground Truth Steps         : {total_gt_steps}",
        f"Step Precision             : {step_precision:6.2f}%",
        f"Step Recall                : {step_recall:6.2f}%",
        f"Step F1                    : {step_f1:6.2f}%",
        "",
        "--- Field-Level Accuracies (Aligned Positions) ---",
    ]
    for f, acc in metrics["field_accuracies"].items():
        lines.append(f"  - {f:15s}: {acc:6.2f}% ({field_correct[f]}/{field_total})")

    lines.extend([
        "",
        "--- Status Breakdown ---",
    ])
    for st, counts in status_breakdown.items():
        if counts["gt"] > 0:
            st_acc = f"Acc={(counts['correct'] / counts['gt'] * 100):6.2f}%"
        else:
            st_acc = "Acc=   N/A "
        lines.append(
            f"  - {st:15s}: {st_acc} (Correct: {counts['correct']:2d}, GT: {counts['gt']:2d}, Pred: {counts['pred']:2d})"
        )

    if mismatches:
        lines.extend([
            "",
            "--- First Discrepancies Sample ---",
        ])
        for m in mismatches:
            lines.append(f"  * {m}")

    lines.append("===========================================================")
    report_text = "\n".join(lines)
    return metrics, report_text


def main():
    parser = argparse.ArgumentParser(description="Evaluate deletion audit predictions against ground truth.")
    parser.add_argument(
        "--pred",
        default="dataset/sample_output.csv",
        help="Path to predictions CSV (defaults to dataset/sample_output.csv)",
    )
    parser.add_argument(
        "--truth",
        default="dataset/sample_output.csv",
        help="Path to ground-truth CSV (defaults to dataset/sample_output.csv)",
    )
    args = parser.parse_args()

    try:
        metrics, report = evaluate(args.pred, args.truth)
        print(report)
    except Exception as e:
        print(f"Evaluation Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
