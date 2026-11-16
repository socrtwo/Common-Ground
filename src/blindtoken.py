"""
Blind-RSA anonymous credential tokens for Common Ground (PROTOTYPE).

Roles:
  Issuer   - run by ICE (or an ICE-designated office). Checks employment
             via PIV/SSO, then signs BLINDED tokens. Never sees the token.
  Holder   - the agent. Creates a random token, blinds it, gets it signed,
             unblinds it, redeems it at the platform.
  Verifier - the platform. Checks the signature against the issuer's
             published public key for that epoch; records a nullifier so a
             token can only be redeemed once.

Scheme: RSA full-domain-hash blind signature. Production must use an audited
RFC 9474 (RSABSSA) implementation inside a Privacy Pass (RFC 9576/9578) flow.
"""
import hashlib, json, os, secrets, sqlite3, time
from math import gcd
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def _fdh(msg: bytes, n: int) -> int:
    """Full-domain hash: expand SHA-256 to modulus length, reduce mod n."""
    k = (n.bit_length() + 7) // 8
    out, ctr = b"", 0
    while len(out) < k:
        out += hashlib.sha256(b"CG-FDH" + ctr.to_bytes(4, "big") + msg).digest()
        ctr += 1
    return int.from_bytes(out[:k], "big") % n

def _b64i(i: int) -> str: return hex(i)
def _i(s: str) -> int: return int(s, 16)

# ---------------------------------------------------------------- Issuer
class Issuer:
    """One RSA key per epoch. Old epochs expire, so separated employees
    simply cannot renew -- no per-person revocation list needed."""
    def __init__(self, keydir: str, tokens_per_epoch: int = 3):
        self.keydir, self.quota = keydir, tokens_per_epoch
        os.makedirs(keydir, exist_ok=True)
        self.db = sqlite3.connect(os.path.join(keydir, "issuance.db"))
        # Stores ONLY a count per employee per epoch, never what was signed.
        self.db.execute("CREATE TABLE IF NOT EXISTS quota"
                        "(emp_hash TEXT, epoch TEXT, n INT, PRIMARY KEY(emp_hash, epoch))")

    def _keypath(self, epoch): return os.path.join(self.keydir, f"{epoch}.pem")

    def new_epoch_key(self, epoch: str):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with open(self._keypath(epoch), "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return self.public_key(epoch)

    def _priv(self, epoch):
        with open(self._keypath(epoch), "rb") as f:
            return serialization.load_pem_private_key(f.read(), None)

    def public_key(self, epoch: str) -> dict:
        pub = self._priv(epoch).public_key().public_numbers()
        return {"epoch": epoch, "n": _b64i(pub.n), "e": pub.e}

    def sign_blinded(self, employee_id: str, epoch: str, blinded_hex: str) -> str:
        """Call ONLY after agency SSO/PIV authentication of employee_id."""
        emp_hash = hashlib.sha256(f"{epoch}:{employee_id}".encode()).hexdigest()
        row = self.db.execute("SELECT n FROM quota WHERE emp_hash=? AND epoch=?",
                              (emp_hash, epoch)).fetchone()
        used = row[0] if row else 0
        if used >= self.quota:
            raise PermissionError("token quota for this epoch exhausted")
        self.db.execute("INSERT OR REPLACE INTO quota VALUES (?,?,?)",
                        (emp_hash, epoch, used + 1)); self.db.commit()
        priv = self._priv(epoch).private_numbers()
        n = priv.public_numbers.n
        return _b64i(pow(_i(blinded_hex), priv.d, n))

# ---------------------------------------------------------------- Holder
class Holder:
    def __init__(self, pubkey: dict):
        self.pk = pubkey; self.n = _i(pubkey["n"]); self.e = pubkey["e"]

    def prepare(self):
        """Returns (state_to_keep_secret, blinded_value_to_send_issuer)."""
        token = {"epoch": self.pk["epoch"], "nonce": secrets.token_hex(32)}
        msg = json.dumps(token, sort_keys=True).encode()
        while True:
            r = secrets.randbelow(self.n - 2) + 2
            if gcd(r, self.n) == 1: break
        blinded = (_fdh(msg, self.n) * pow(r, self.e, self.n)) % self.n
        return {"token": token, "r": _b64i(r)}, _b64i(blinded)

    def finalize(self, state: dict, blind_sig_hex: str) -> dict:
        r_inv = pow(_i(state["r"]), -1, self.n)
        sig = (_i(blind_sig_hex) * r_inv) % self.n
        return {**state["token"], "sig": _b64i(sig)}

# ---------------------------------------------------------------- Verifier
class Verifier:
    def __init__(self, keyring: dict, db):
        self.keyring = keyring          # epoch -> pubkey dict (pinned)
        # db: a path, or an existing sqlite3 connection to share (avoids locks)
        self.db = db if isinstance(db, sqlite3.Connection) else sqlite3.connect(db)
        self.db.execute("CREATE TABLE IF NOT EXISTS spent(nullifier TEXT PRIMARY KEY, epoch TEXT)")

    def redeem(self, tok: dict) -> bool:
        pk = self.keyring.get(tok.get("epoch"))
        if not pk: return False                         # unknown/expired epoch
        n, e = _i(pk["n"]), pk["e"]
        msg = json.dumps({"epoch": tok["epoch"], "nonce": tok["nonce"]}, sort_keys=True).encode()
        if pow(_i(tok["sig"]), e, n) != _fdh(msg, n): return False
        nullifier = hashlib.sha256(bytes.fromhex(tok["nonce"])).hexdigest()
        try:
            self.db.execute("INSERT INTO spent VALUES (?,?)", (nullifier, tok["epoch"]))
            self.db.commit()
        except sqlite3.IntegrityError:
            self.db.rollback()
            return False                                # double-spend
        return True
