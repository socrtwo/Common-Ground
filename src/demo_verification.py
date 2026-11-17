"""End-to-end demo of the credential protocol:  python3 src/demo_verification.py

Plays all three roles (issuer, agent, platform) in one process, using a
throwaway directory that is deleted on exit.
"""
import os
import tempfile

from blindtoken import Holder, Issuer, QuotaExceeded, Verifier


def main() -> None:
    epoch = "2026-Q4"
    with tempfile.TemporaryDirectory() as tmp:
        issuer = Issuer(os.path.join(tmp, "issuer"), tokens_per_epoch=3)
        pub = issuer.new_epoch_key(epoch)                 # the agency publishes this
        print("Published key for", epoch, f"({int(pub['n'], 16).bit_length()}-bit modulus)")

        agent = Holder(pub)
        state, blinded = agent.prepare()                  # on the agent's own device
        blind_sig = issuer.sign_blinded("EMP-12345", epoch, blinded)   # after PIV login
        token = agent.finalize(state, blind_sig)          # issuer never saw this token

        platform = Verifier({epoch: pub}, os.path.join(tmp, "platform.db"))
        print("First redemption: ", platform.redeem(token))
        print("Replay attempt:   ", platform.redeem(token))

        forged = dict(token, nonce="00" * 32)
        print("Forged token:     ", platform.redeem(forged))

        for i in range(1, 4):                             # quota is 3, one already used
            try:
                _, b = agent.prepare()
                issuer.sign_blinded("EMP-12345", epoch, b)
                print(f"Extra issuance {i}: ok")
            except QuotaExceeded as ex:
                print(f"Extra issuance {i}: refused ({ex})")

        platform.db.close()
        issuer.close()


if __name__ == "__main__":
    main()
