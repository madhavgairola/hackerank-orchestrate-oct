import csv
with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if '2026-09-15T09:5' in r.get('reported_at', '') or '2026-09-15T10:0' in r.get('reported_at', ''):
            print("deletion_requests:", r['case_id'], r['email'], r['reported_at'])

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if '2026-09-15T09:5' in r.get('reported_at', '') or '2026-09-15T10:0' in r.get('reported_at', ''):
            print("sample_deletion_requests:", r['case_id'], r['email'], r['reported_at'])
