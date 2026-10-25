import sys
sys.path.insert(0, './code')
import csv
from identity import IdentityGraph
from evidence_store import EvidenceStore

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = EvidenceStore('dataset', idg)
u11 = idg.resolve_user('novak.tomasz@icloud.com')
print("user_11 (user_32) resources:", store.user_to_resources.get(u11.user_id))
print("resource_to_user for analytics_2034:", store.resource_to_user.get('analytics_2034'))
print("resource_to_user for analytics_5715:", store.resource_to_user.get('analytics_5715'))
