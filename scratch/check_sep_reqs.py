import csv
with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if r['reported_at'] == '2026-09-05T12:00:00Z':
            print("deletion_req:", r['case_id'], r['email'], r['reported_status'], r['requested_at'])

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if r['reported_at'] == '2026-09-05T12:00:00Z':
            print("sample_req:  ", r['case_id'], r['email'], r['reported_status'], r['requested_at'])
