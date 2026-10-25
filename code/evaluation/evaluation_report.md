# Deletion-Audit Evaluation Report: Ghost Data Still Exists

## Executive Summary
This evaluation report assesses the performance of the AI-powered deletion-audit agent built for the HackerRank Orchestrate (October 2026) challenge: **Ghost Data Still Exists**.

The solution implements a deterministic, evidence-grounded audit pipeline in Python comprising:
1. An **Identity Graph** (`code/identity.py`) for resolving current and historical identifiers across name, email, phone, and email hashes.
2. An **Evidence Store** (`code/evidence_store.py`) that indexes structured JSON, SQL replicas, logs, TXT records, PDF documents, and system activity logs with strict temporal awareness (`audit_at` cutoff enforcement).
3. A **Policy Engine** (`code/policy_engine.py`) that applies `dataset/deletion_rules.csv` to reconstruct ground-truth resource states, detect recreation risks and exposed PII, and generate ordered remediation plans with verification checks.

---

## Benchmark Evaluation Results (Sample Dataset)

The pipeline was benchmarked against the 32 ground-truth cases in `dataset/sample_output.csv` using the automated evaluation harness (`code/evaluation/main.py`).

### High-Level Accuracy Metrics
| Metric | Result | Benchmark Target | Pass / Fail |
|---|---|---|---|
| **Case-Level Status Accuracy** | **100.00% (32 / 32)** | 100% | **PASS** |
| **Step-Count Accuracy** | **87.50% (28 / 32)** | > 70% | **PASS** |
| **Full Sequence Accuracy** | **84.38% (27 / 32)** | > 60% | **PASS** |

### Status Category Breakdown
| Deletion Status | Ground Truth Cases | Predicted Cases | Correct Predictions | Accuracy |
|---|---|---|---|---|
| `COMPLETE` | 10 | 10 | 10 | **100.00%** |
| `INCOMPLETE` | 22 | 22 | 22 | **100.00%** |
| `NOT_APPLICABLE` | 0 | 0 | 0 | **N/A** (no GT cases) |

### Step-Level Precision, Recall, and F1
Evaluating exact match across all step tuples `(phase, system_id, resource_id, operation, state, evidence_id)`:
- **Total Predicted Steps**: 189
- **Total Ground Truth Steps**: 193
- **Step Precision**: **97.35%**
- **Step Recall**: **95.34%**
- **Step F1 Score**: **96.34%**

### Field-Level Accuracies (Aligned Positions)
| Step Attribute | Accuracy | Matching Fields / Total Aligned |
|---|---|---|
| `phase` | **100.00%** | 189 / 189 |
| `system_id` | **97.88%** | 185 / 189 |
| `resource_id` | **97.35%** | 184 / 189 |
| `operation` | **97.88%** | 185 / 189 |
| `state` | **97.88%** | 185 / 189 |
| `evidence_id` | **100.00%** | 189 / 189 |

---

## Full Dataset Execution (518 Cases)

The agent was evaluated end-to-end on all 518 evaluation requests in `dataset/deletion_requests.csv`, generating the final `output.csv`.

- **Total Cases Processed**: 518 / 518 (100.0%)
- **Total Execution Time**: 15.32 seconds (~29.6 ms / case)
- **Status Breakdown**:
  - `COMPLETE`: 151 cases (29.2%)
  - `INCOMPLETE`: 357 cases (68.9%)
  - `NOT_APPLICABLE`: 10 cases (1.9%)
- **Contract & Validation Checks**:
  - Header & Column Ordering (`case_id,deletion_status,steps_json`): **PASS** (0 errors)
  - Output Row Count & Key Sorting (case_001 to case_518): **PASS** (0 errors)
  - Phase Progression (`FINDING` -> `REMEDIATION` -> `VERIFICATION`): **PASS** (0 errors)
  - Sequential Step Numbering (1..N): **PASS** (0 errors)
  - Finding Evidence Grounding (all findings cite visible participant evidence): **PASS** (0 errors)
  - Evidence Cutoff Enforcement (`evidence captured_at <= case audit_at`): **PASS** (0 violations)
  - Total Formatting / Status / Temporal Errors: **0**

---

## Participant-Created Evaluation Cases

To test edge cases outside the standard sample distribution, three realistic test cases were formulated and validated against the deletion policy:

### Custom Case 1: Subject Access Request (GDPR Art 15) vs. Erasure (Art 17)
- **Case ID**: `custom_case_001`
- **Request Text**: *"Please provide an export of all my personal data, transaction history, and support logs for my records under privacy regulations."*
- **Subject Context**: `user_991`, `request_email: alex.rivera@example.com`
- **Audit Cutoff**: `2026-09-20T12:00:00Z`
- **Expected Status**: `NOT_APPLICABLE`
- **Expected Steps**: `[]`
- **Rationale**: The request text specifies a Subject Access / Export Request, not an erasure / deletion request. Even if database records and active accounts exist, the deletion workflow must not execute. The agent correctly returns `NOT_APPLICABLE` with `steps_json=[]`.

### Custom Case 2: Compliant Account Tombstone Preservation
- **Case ID**: `custom_case_002`
- **Request Text**: *"I want to close my account and have my profile information completely erased."*
- **Subject Context**: `user_992`, `request_email: jordan.lee@example.com`
- **Audit Cutoff**: `2026-09-21T15:00:00Z`
- **Evidence State**:
  - `account_service` holds tombstone record `account_992` with `user_id = user_992`, but `email`, `name`, and `phone` are redacted / null.
  - Captured in snapshot `evidence_04` before `audit_at`.
- **Deletion Rule**: Category `ACCOUNT_TOMBSTONE` specifies `REDACT` action, retaining the stable subject reference while removing prohibited direct identifiers.
- **Expected Status**: `COMPLETE`
- **Expected Steps**:
  ```json
  [
    {
      "step_no": 1,
      "phase": "VERIFICATION",
      "system_id": "account_service",
      "resource_id": "account_992",
      "operation": "VERIFY_RECORD_REDACTED",
      "state": "REDACTED",
      "evidence_id": "evidence_04"
    }
  ]
  ```
- **Rationale**: An account tombstone stripped of direct PII complies with the deletion policy. The agent avoids false positive `REPORT_REMAINING_RECORD` findings and verifies the compliant tombstone state.

### Custom Case 3: Active Change Data Capture (CDC) Sync Recreating Deleted Records
- **Case ID**: `custom_case_003`
- **Request Text**: *"Please delete all my accounts and data immediately."*
- **Subject Context**: `user_993`, `request_email: taylor.morgan@example.com`
- **Audit Cutoff**: `2026-09-22T10:00:00Z`
- **Evidence State**:
  - Primary database `user_db` has deleted the user profile (`ABSENT`).
  - Read-replica `reporting_db` still contains the user profile (`PRESENT`) due to an active replication task `data_flow_09` running between `user_db` and `reporting_db`.
  - Backup archive `backup_s3_user_993` is present with restore enabled (`ACTIVE`).
- **Expected Status**: `INCOMPLETE`
- **Expected Steps**:
  ```json
  [
    {
      "step_no": 1,
      "phase": "FINDING",
      "system_id": "cdc_pipeline",
      "resource_id": "data_flow_09",
      "operation": "REPORT_ACTIVE_DATA_FLOW",
      "state": "ACTIVE",
      "evidence_id": "evidence_08"
    },
    {
      "step_no": 2,
      "phase": "FINDING",
      "system_id": "backup_service",
      "resource_id": "backup_s3_user_993",
      "operation": "REPORT_RESTORE_RISK",
      "state": "ACTIVE",
      "evidence_id": "evidence_09"
    },
    {
      "step_no": 3,
      "phase": "FINDING",
      "system_id": "reporting_db",
      "resource_id": "profile_993",
      "operation": "REPORT_REMAINING_RECORD",
      "state": "PRESENT",
      "evidence_id": "evidence_10"
    },
    {
      "step_no": 4,
      "phase": "REMEDIATION",
      "system_id": "cdc_pipeline",
      "resource_id": "data_flow_09",
      "operation": "DISABLE_DATA_FLOW",
      "state": "DISABLED",
      "evidence_id": ""
    },
    {
      "step_no": 5,
      "phase": "REMEDIATION",
      "system_id": "backup_service",
      "resource_id": "backup_s3_user_993",
      "operation": "BLOCK_RESTORE",
      "state": "BLOCKED",
      "evidence_id": ""
    },
    {
      "step_no": 6,
      "phase": "REMEDIATION",
      "system_id": "reporting_db",
      "resource_id": "profile_993",
      "operation": "DELETE_RECORD",
      "state": "ABSENT",
      "evidence_id": ""
    },
    {
      "step_no": 7,
      "phase": "VERIFICATION",
      "system_id": "cdc_pipeline",
      "resource_id": "data_flow_09",
      "operation": "VERIFY_DATA_FLOW_DISABLED",
      "state": "DISABLED",
      "evidence_id": ""
    },
    {
      "step_no": 8,
      "phase": "VERIFICATION",
      "system_id": "backup_service",
      "resource_id": "backup_s3_user_993",
      "operation": "VERIFY_RESTORE_BLOCKED",
      "state": "BLOCKED",
      "evidence_id": ""
    },
    {
      "step_no": 9,
      "phase": "VERIFICATION",
      "system_id": "reporting_db",
      "resource_id": "profile_993",
      "operation": "VERIFY_RECORD_ABSENT",
      "state": "ABSENT",
      "evidence_id": ""
    }
  ]
  ```
- **Rationale**: Remediation dependency ordering requires stopping active data flows and blocking restores BEFORE removing residual records; otherwise, ongoing replication will immediately recreate the deleted record.

---

## Failures Found and Iterative Improvements Made

During engineering, testing, and full-dataset validation, several critical edge cases and systemic failure modes were discovered and systematically resolved:

1. **Replication Drift & False Deletion Claims**:
   - *Failure*: Services frequently logged `deletion_workflow = COMPLETE`, while SQL read-replicas and regional shards still contained live user rows.
   - *Improvement*: Designed `evidence_store.py` to inspect actual SQLite tables and SQL dump statements across all regional and reporting replicas rather than accepting workflow claims.

2. **JSON Record Bundles and Snapshot Hierarchy**:
   - *Failure*: In search index exports and nested JSON logs, document hits were encapsulated inside `hits.documents[]` or `record_json` string fields. Flat parser treated these as absent.
   - *Improvement*: Added recursive document unpackers and stringified JSON decoders in `_load_json_records`, extracting nested secondary emails, user IDs, and resource metadata.

3. **Temporal Cutoff & Manifest Capture Boundary Violations**:
   - *Failure*: An early fallback mechanism cited an evidence file (`evidence_54`) that was captured in October, violating temporal cutoffs for cases whose `audit_at` was in February or March.
   - *Improvement*: Implemented dynamic, cutoff-bounded manifest searches (`fmeta["captured_at"] <= audit_at`). If an evidence file was captured after `audit_at`, it cannot be cited. If absence cannot be verified with pre-cutoff evidence, the case is conservatively and safely marked `INCOMPLETE`.

4. **Multi-Identity Historical Linkage**:
   - *Failure*: Users submitted deletion requests using historical or changed emails that differed from their current primary email snapshot in `user_identities.csv`.
   - *Improvement*: Implemented a bidirectional `IdentityGraph` combining `user_identities.csv` and `user_audit_log.csv`, indexing historical emails, normalized phone numbers, and SHA-256 email hashes.

5. **Strict Remediation Phase and Operation Ordering**:
   - *Failure*: Initial step generator interleaved remediation steps with findings.
   - *Improvement*: Implemented deterministic priority matrices enforcing exact phase transitions (`FINDING` -> `REMEDIATION` -> `VERIFICATION`) and intra-phase operation ranks:
     - Finding: `REPORT_ACTIVE_DATA_FLOW` -> `REPORT_RESTORE_RISK` -> `REPORT_REMAINING_RECORD` -> `REPORT_EXPOSED_PII`
     - Remediation: `DISABLE_DATA_FLOW` -> `BLOCK_RESTORE` -> `DELETE_RECORD` -> `REDACT_RECORD` -> `ANONYMIZE_RECORD`
     - Verification: `VERIFY_DATA_FLOW_DISABLED` -> `VERIFY_RESTORE_BLOCKED` -> `VERIFY_RECORD_ABSENT` -> `VERIFY_RECORD_REDACTED` -> `VERIFY_RECORD_ANONYMIZED` -> `VERIFY_RECORD_PRESENT`

---

## Conclusion
The deterministic Python deletion-audit system achieves 100% case-level accuracy on the public benchmark, zero contract violations across all 518 evaluation requests, and processes the full dataset in under 30 seconds with zero runtime LLM costs.
