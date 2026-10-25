import sys
sys.path.insert(0, "code")
import pandas as pd
from identity import IdentityGraph
from evidence_store import EvidenceStore

idg = IdentityGraph("dataset/user_identities.csv", "dataset/user_audit_log.csv")
store = EvidenceStore("dataset", idg)

u48 = idg.resolve_user("user_48")
u50 = idg.resolve_user("user_50")

print("user_48 linked resources:", store.user_to_resources.get("user_48", set()))
print("user_50 linked resources:", store.user_to_resources.get("user_50", set()))
