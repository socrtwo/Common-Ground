"""End-to-end demo: python3 src/demo_verification.py"""
import json, os, tempfile
from blindtoken import Issuer, Holder, Verifier

tmp = tempfile.mkdtemp()
epoch = "2026-Q4"

issuer = Issuer(os.path.join(tmp, "issuer"), tokens_per_epoch=3)
pub = issuer.new_epoch_key(epoch)               # ICE publishes this
print("Published key for", epoch, f"({int(pub['n'], 16).bit_length()}-bit modulus)")

agent = Holder(pub)
state, blinded = agent.prepare()                # on agent's own device
blind_sig = issuer.sign_blinded("EMP-12345", epoch, blinded)   # after PIV login
token = agent.finalize(state, blind_sig)        # issuer never saw this token

platform = Verifier({epoch: pub}, os.path.join(tmp, "platform.db"))
print("First redemption: ", platform.redeem(token))
print("Replay attempt:   ", platform.redeem(token))

forged = dict(token, nonce="00" * 32)
print("Forged token:     ", platform.redeem(forged))

for i in range(3):
    try:
        _, b = agent.prepare(); issuer.sign_blinded("EMP-12345", epoch, b)
        print(f"Extra issuance {i+1}: ok")
    except PermissionError as ex:
        print(f"Extra issuance {i+1}: refused ({ex})")
