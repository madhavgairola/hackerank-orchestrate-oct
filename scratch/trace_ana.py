import sys
sys.path.insert(0, './code')
from identity import IdentityGraph
from evidence_store import EvidenceStore

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = EvidenceStore('dataset', idg)
print("resource_to_user for analytics_5715:", store.resource_to_user.get('analytics_5715'))
print("resource_to_user for analytics_9447:", store.resource_to_user.get('analytics_9447'))
