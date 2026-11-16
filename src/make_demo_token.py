"""
TESTING ONLY: stands in for the agency issuer so you can try the agent badge.
Writes keyring.json (the public key the site trusts) and prints one token.
Real deployment: ICE runs Issuer behind PIV/SSO; the site only gets its public key.
"""
import json, os
from blindtoken import Issuer, Holder

epoch = "demo-epoch"
iss = Issuer("demo_issuer", tokens_per_epoch=100)
pub = iss.public_key(epoch) if os.path.exists(f"demo_issuer/{epoch}.pem") else iss.new_epoch_key(epoch)
json.dump({epoch: pub}, open("keyring.json", "w"))
holder = Holder(pub)
state, blinded = holder.prepare()
token = holder.finalize(state, iss.sign_blinded("TEST-EMPLOYEE", epoch, blinded))
print(json.dumps(token))
