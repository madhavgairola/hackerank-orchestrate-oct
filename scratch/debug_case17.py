import sys
sys.path.insert(0, './code')
import csv
from identity import IdentityGraph
from evidence_store import EvidenceStore

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = EvidenceStore('dataset', idg)
u17 = idg.resolve_user('leonie.g9352@outlook.com')
print("user_17 linked resources:", store.user_to_resources.get(u17.user_id))
print("resource_to_user for account_4092:", store.resource_to_user.get('account_4092'))
print("resource_to_user for account_6523:", store.resource_to_user.get('account_6523'))
print("resource_to_user for tombstone_17:", store.resource_to_user.get('tombstone_17'))
