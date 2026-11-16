"""
TESTING ONLY: stands in for the agency issuer so you can try the agent badge.

Creates ./demo_issuer/ (a throwaway signing key), writes the keyring file the
site trusts, and prints one token to paste at /verify. Run it again for
another token.

Real deployment: the agency runs Issuer behind PIV/SSO and the site only ever
receives its public key. Anyone who can read demo_issuer/ can mint badges, so
never point a public site at a keyring produced by this script.
"""
import json
import os
import sys

from blindtoken import Holder, Issuer, load_keyring

EPOCH = "demo-epoch"
KEYRING = os.environ.get("CG_KEYRING", "keyring.json")


def main() -> int:
    try:
        ring = load_keyring(KEYRING)
    except ValueError as ex:
        print(f"Refusing to touch {KEYRING}: {ex}", file=sys.stderr)
        return 1
    if set(ring) - {EPOCH}:
        print(f"Refusing to overwrite {KEYRING}: it holds non-demo epochs "
              f"({', '.join(sorted(set(ring) - {EPOCH}))}).", file=sys.stderr)
        return 1

    issuer = Issuer("demo_issuer", tokens_per_epoch=100)
    pub = issuer.public_key(EPOCH) if issuer.has_epoch(EPOCH) else issuer.new_epoch_key(EPOCH)
    with open(KEYRING, "w", encoding="utf-8") as f:
        json.dump({EPOCH: pub}, f)

    holder = Holder(pub)
    state, blinded = holder.prepare()
    token = holder.finalize(state, issuer.sign_blinded("TEST-EMPLOYEE", EPOCH, blinded))
    issuer.close()
    print(json.dumps(token))
    return 0


if __name__ == "__main__":
    sys.exit(main())
