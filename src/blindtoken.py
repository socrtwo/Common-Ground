"""
Blind-RSA anonymous credential tokens for Common Ground (PROTOTYPE).

Roles:
  Issuer   - run by the agency (or an office it designates). Checks employment
             via PIV/SSO, then signs BLINDED tokens. Never sees the token.
  Holder   - the agent. Creates a random token, blinds it, gets it signed,
             unblinds it, redeems it at the platform.
  Verifier - the platform. Checks the signature against the issuer's
             published public key for that epoch and records a nullifier so
             a token can be redeemed only once.

Scheme: RSA full-domain-hash blind signature (textbook Chaum). This module is
unaudited demonstration code. Production must use an audited RFC 9474
(RSABSSA) implementation inside a Privacy Pass (RFC 9576/9578) flow.

Wire formats (all integers are lowercase hex strings without a 0x prefix):
  public key  {"epoch": str, "n": hex, "e": 65537, "expires": unix-seconds?}
  token       {"epoch": str, "nonce": 64 hex chars, "sig": hex}
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from math import gcd

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PUBLIC_EXPONENT = 65537
MIN_MODULUS_BITS = 2048
DEFAULT_MODULUS_BITS = 3072
NONCE_HEX_LEN = 64

# Epoch names end up in file names and signed messages, so keep them boring.
_EPOCH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
_HEX_RE = re.compile(r"[0-9a-f]{1,2048}")
_NONCE_RE = re.compile(rf"[0-9a-f]{{{NONCE_HEX_LEN}}}")


# ------------------------------------------------------------------ encoding
def _to_hex(i: int) -> str:
    return format(i, "x")


def _from_hex(s) -> int:
    """Strict hex parser; int(s, 16) alone accepts signs, 0x, '_' and spaces."""
    if not isinstance(s, str) or not _HEX_RE.fullmatch(s):
        raise ValueError("expected a lowercase hex string")
    return int(s, 16)


def valid_epoch(epoch) -> bool:
    return isinstance(epoch, str) and _EPOCH_RE.fullmatch(epoch) is not None


def _check_epoch(epoch) -> str:
    if not valid_epoch(epoch):
        raise ValueError("invalid epoch name")
    return epoch


def _token_message(epoch: str, nonce: str) -> bytes:
    """Canonical byte string that is signed. Neither field can contain NUL."""
    return b"common-ground/token/v1\x00" + epoch.encode() + b"\x00" + nonce.encode()


def _fdh(msg: bytes, n: int) -> int:
    """Full-domain hash onto Z_n.

    Squeezes 16 bytes more than the modulus length from SHAKE-256 so the
    reduction mod n is statistically uniform.
    """
    k = (n.bit_length() + 7) // 8
    wide = hashlib.shake_256(b"common-ground/fdh/v1\x00" + msg).digest(k + 16)
    return int.from_bytes(wide, "big") % n


def _random_unit(n: int) -> int:
    """Random element of Z_n* (used as a blinding factor)."""
    while True:
        r = secrets.randbelow(n - 2) + 2
        if gcd(r, n) == 1:
            return r


def parse_public_key(pk) -> tuple[int, int]:
    """Validate a published key dict and return (n, e)."""
    if not isinstance(pk, dict):
        raise ValueError("public key must be an object")
    _check_epoch(pk.get("epoch"))
    n, e = _from_hex(pk.get("n")), pk.get("e")
    if e != PUBLIC_EXPONENT or isinstance(e, bool):
        raise ValueError(f"public exponent must be {PUBLIC_EXPONENT}")
    if n.bit_length() < MIN_MODULUS_BITS or n % 2 == 0:
        raise ValueError(f"modulus must be odd and at least {MIN_MODULUS_BITS} bits")
    expires = pk.get("expires")
    if expires is not None and (isinstance(expires, bool) or not isinstance(expires, int)):
        raise ValueError("expires must be an integer Unix timestamp")
    return n, e


def key_is_active(pk: dict, now: float | None = None) -> bool:
    """True unless the key carries an 'expires' timestamp that has passed."""
    expires = pk.get("expires")
    return expires is None or (time.time() if now is None else now) < expires


def load_keyring(path: str) -> dict:
    """Read the platform's pinned keyring: {epoch: public key dict}.

    A missing file is an empty keyring. A malformed file raises ValueError so
    the caller can fail closed.
    """
    try:
        with open(path, encoding="utf-8") as f:
            ring = json.load(f)
    except FileNotFoundError:
        return {}
    if not isinstance(ring, dict):
        raise ValueError("keyring must be a JSON object keyed by epoch")
    for epoch, pk in ring.items():
        parse_public_key(pk)
        if pk["epoch"] != epoch:
            raise ValueError(f"keyring entry {epoch!r} holds a key for another epoch")
    return ring


# -------------------------------------------------------------------- Issuer
class QuotaExceeded(PermissionError):
    """The employee has already received this epoch's allotment of tokens."""


class Issuer:
    """One RSA key per epoch. Old epochs expire, so separated employees
    simply cannot renew -- no per-person revocation list is needed.

    The issuer stores only a per-employee, per-epoch COUNT, keyed by an HMAC
    of the employee ID under a secret that never leaves the key directory.
    It never stores, or sees, what it signed.
    """

    def __init__(self, keydir: str, tokens_per_epoch: int = 3):
        if tokens_per_epoch < 1:
            raise ValueError("tokens_per_epoch must be at least 1")
        self.keydir, self.quota = keydir, tokens_per_epoch
        os.makedirs(keydir, mode=0o700, exist_ok=True)
        self._mac_key = self._load_or_create_mac_key()
        self.db = sqlite3.connect(os.path.join(keydir, "issuance.db"))
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS quota("
            "emp_hash TEXT NOT NULL, epoch TEXT NOT NULL, n INTEGER NOT NULL, "
            "PRIMARY KEY(emp_hash, epoch))"
        )
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    @staticmethod
    def _write_private(path: str, data: bytes) -> None:
        """Create a file readable only by the owner; never overwrite one."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)

    def _load_or_create_mac_key(self) -> bytes:
        path = os.path.join(self.keydir, "quota.key")
        try:
            self._write_private(path, secrets.token_bytes(32))
        except FileExistsError:
            pass
        with open(path, "rb") as f:
            return f.read()

    def _keypath(self, epoch: str) -> str:
        return os.path.join(self.keydir, f"{_check_epoch(epoch)}.pem")

    def has_epoch(self, epoch: str) -> bool:
        return os.path.exists(self._keypath(epoch))

    def new_epoch_key(self, epoch: str, expires: int | None = None,
                      key_size: int = DEFAULT_MODULUS_BITS) -> dict:
        """Generate the signing key for an epoch and return its public half.

        Raises FileExistsError rather than replace an existing epoch key,
        which would invalidate every token already issued under it.
        """
        if key_size < MIN_MODULUS_BITS:
            raise ValueError(f"key_size must be at least {MIN_MODULUS_BITS}")
        key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=key_size)
        self._write_private(self._keypath(epoch), key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        return self.public_key(epoch, expires)

    def _private_numbers(self, epoch: str):
        try:
            with open(self._keypath(epoch), "rb") as f:
                key = serialization.load_pem_private_key(f.read(), None)
        except FileNotFoundError:
            raise LookupError(f"no signing key for epoch {epoch!r}") from None
        return key.private_numbers()

    def public_key(self, epoch: str, expires: int | None = None) -> dict:
        """The value the agency publishes and the platform pins."""
        pub = self._private_numbers(epoch).public_numbers
        pk = {"epoch": epoch, "n": _to_hex(pub.n), "e": pub.e}
        if expires is not None:
            pk["expires"] = int(expires)
        return pk

    def sign_blinded(self, employee_id: str, epoch: str, blinded_hex: str) -> str:
        """Sign one blinded token. Call ONLY after agency SSO/PIV
        authentication of employee_id.

        Raises QuotaExceeded, LookupError (unknown epoch) or ValueError
        (malformed request). Quota is consumed only if a signature is returned.
        """
        priv = self._private_numbers(epoch)
        n, e, d = priv.public_numbers.n, priv.public_numbers.e, priv.d
        blinded = _from_hex(blinded_hex)
        if not 0 < blinded < n:
            raise ValueError("blinded value out of range")

        # Base blinding hides the (requester-chosen) input from pow()'s timing;
        # the final check catches a faulted computation before it leaves.
        r = _random_unit(n)
        sig = (pow(blinded * pow(r, e, n) % n, d, n) * pow(r, -1, n)) % n
        if pow(sig, e, n) != blinded:
            raise RuntimeError("signature self-check failed")

        emp_hash = hmac.new(self._mac_key, f"{epoch}\x00{employee_id}".encode(),
                            hashlib.sha256).hexdigest()
        # Single statement, so two concurrent requests cannot both pass a
        # check-then-increment.
        cur = self.db.execute(
            "INSERT INTO quota(emp_hash, epoch, n) VALUES(?,?,1) "
            "ON CONFLICT(emp_hash, epoch) DO UPDATE SET n = n + 1 WHERE n < ?",
            (emp_hash, epoch, self.quota),
        )
        self.db.commit()
        if cur.rowcount != 1:
            raise QuotaExceeded("token quota for this epoch exhausted")
        return _to_hex(sig)


# -------------------------------------------------------------------- Holder
class Holder:
    """Runs on the agent's own device."""

    def __init__(self, pubkey: dict):
        self.n, self.e = parse_public_key(pubkey)
        self.epoch = pubkey["epoch"]

    def prepare(self) -> tuple[dict, str]:
        """Returns (state_to_keep_secret, blinded_value_to_send_issuer)."""
        nonce = secrets.token_hex(NONCE_HEX_LEN // 2)
        r = _random_unit(self.n)
        m = _fdh(_token_message(self.epoch, nonce), self.n)
        blinded = (m * pow(r, self.e, self.n)) % self.n
        return {"epoch": self.epoch, "nonce": nonce, "r": _to_hex(r)}, _to_hex(blinded)

    def finalize(self, state: dict, blind_sig_hex: str) -> dict:
        """Unblind the issuer's response into a redeemable token.

        Raises ValueError if the issuer returned something that is not a
        valid signature, so a bad token is caught before it is spent.
        """
        r = _from_hex(state["r"])
        sig = (_from_hex(blind_sig_hex) * pow(r, -1, self.n)) % self.n
        m = _fdh(_token_message(state["epoch"], state["nonce"]), self.n)
        if pow(sig, self.e, self.n) != m:
            raise ValueError("issuer returned an invalid signature")
        return {"epoch": state["epoch"], "nonce": state["nonce"], "sig": _to_hex(sig)}


# ------------------------------------------------------------------ Verifier
class Verifier:
    """Runs on the platform."""

    SCHEMA = ("CREATE TABLE IF NOT EXISTS spent("
              "nullifier TEXT PRIMARY KEY, epoch TEXT NOT NULL)")

    def __init__(self, keyring: dict, db):
        self.keyring = keyring          # epoch -> public key dict (pinned)
        # db: a path, or an existing sqlite3 connection to share.
        self.db = db if isinstance(db, sqlite3.Connection) else sqlite3.connect(db)
        self.db.execute(self.SCHEMA)

    def redeem(self, tok, commit: bool = True, now: float | None = None) -> bool:
        """Accept a token at most once. Returns False for anything malformed,
        forged, expired or already spent; never raises on untrusted input.

        With commit=False the nullifier is left in the caller's open
        transaction, so the caller can commit it atomically with whatever the
        token unlocks (or roll both back).
        """
        if not isinstance(tok, dict):
            return False
        epoch, nonce = tok.get("epoch"), tok.get("nonce")
        if not valid_epoch(epoch):
            return False
        if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
            return False
        pk = self.keyring.get(epoch)
        if pk is None:
            return False                                # unknown epoch
        try:
            n, e = parse_public_key(pk)
            sig = _from_hex(tok.get("sig"))
        except ValueError:
            return False
        if not key_is_active(pk, now) or not 0 < sig < n:
            return False
        msg = _token_message(epoch, nonce)
        if pow(sig, e, n) != _fdh(msg, n):
            return False                                # forged or wrong key
        nullifier = hashlib.sha256(b"common-ground/nullifier/v1\x00" + msg).hexdigest()
        try:
            self.db.execute("INSERT INTO spent(nullifier, epoch) VALUES(?,?)",
                            (nullifier, epoch))
        except sqlite3.IntegrityError:
            return False                                # double-spend
        if commit:
            self.db.commit()
        return True
