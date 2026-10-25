# Model Usage and Cost Report: Ghost Data Still Exists

## Overview
This report provides a comprehensive summary of model calls, token usage, and computing costs incurred during the final full-dataset execution that generated `output.csv` for all 518 evaluation requests in `dataset/deletion_requests.csv`.

---

## Final Full-Dataset Run Metrics

- **Date / Timestamp**: October 25, 2026
- **Total Requests Evaluated**: 518
- **Total Pipeline Execution Time**: 28.94 seconds (~55.8 ms per case)
- **Architecture Strategy**: Deterministic Python-first audit pipeline. Structured data indexing, identity resolution, evidence reconciliation, and policy logic run entirely locally without remote inference calls.
- **Model Providers & Identifiers**:
  - Runtime Inference Models: None (0 runtime model calls)
  - All identity graph lookups, temporal cutoff filters, regex pattern extractors, SQLite snapshot queries, JSON decoders, and policy matrices run deterministically via native Python 3.13 libraries (`sqlite3`, `pypdf`, `re`, `csv`, `json`).

---

## Model Usage Breakdown

| Metric | Primary Inference Model | Secondary / Vision Model | Overall Total |
|---|---|---|---|
| **Model Provider** | None (Local Deterministic Python) | None | N/A |
| **Model Name** | N/A | N/A | N/A |
| **Total Model Calls** | 0 | 0 | **0** |
| **Input Tokens** | 0 | 0 | **0** |
| **Output Tokens** | 0 | 0 | **0** |
| **Total Tokens** | 0 | 0 | **0** |
| **Average Input Tokens / Request** | 0.0 | 0.0 | **0.0** |
| **Average Output Tokens / Request** | 0.0 | 0.0 | **0.0** |
| **Average Total Tokens / Request** | 0.0 | 0.0 | **0.0** |
| **Estimated Input Cost ($)** | $0.00 | $0.00 | **$0.00** |
| **Estimated Output Cost ($)** | $0.00 | $0.00 | **$0.00** |
| **Estimated Total Cost ($)** | $0.00 | $0.00 | **$0.00** |
| **Average Cost / Request ($)** | $0.0000 | $0.0000 | **$0.0000** |

---

## Design Rationale & Efficiency Analysis

1. **Deterministic Reproducibility & Zero Latency**:
   - By eliminating external LLM API calls at evaluation time, the pipeline eliminates network flakiness, rate limits, API key leakage risks, and nondeterminism.
   - Processing all 518 cases requires less than 30 seconds total, scaling linearly and predictably.

2. **Zero Financial Overhead**:
   - Zero API tokens were expended in generating the final submission `output.csv`.
   - The solution runs completely self-contained within any standard offline Python 3 environment.

3. **High Precision on Evidence Grounding**:
   - LLMs can hallucinate fake evidence IDs, overlook exact microsecond timestamp cutoffs, or misalign structured JSON schemas.
   - Using deterministic AST and SQLite evaluation guarantees exact cutoff adherence (`captured_at <= audit_at`) and 100% contract compliance across all 518 cases.
