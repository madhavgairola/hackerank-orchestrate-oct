import csv

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    for i, r in enumerate(csv.DictReader(f)):
        if (i + 1) in (4, 11, 17, 18, 20, 23, 24, 25, 26, 28, 29):
            print(f"Index {i+1}: case_id={r['case_id']}, email={r['email']}, rep_status={r['reported_status']}, audit_at={r['audit_at']}")
