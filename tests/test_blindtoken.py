import json
import os
import stat

import pytest

import blindtoken
from blindtoken import Holder, Issuer, QuotaExceeded, Verifier, load_keyring, parse_public_key
from conftest import EPOCH


@pytest.fixture
def verifier(tmp_path, pubkey):
    v = Verifier({EPOCH: pubkey}, str(tmp_path / "spent.db"))
    yield v
    v.db.close()


def test_round_trip_and_replay(verifier, mint):
    token = mint()
    assert verifier.redeem(token) is True
    assert verifier.redeem(token) is False            # double-spend


def test_spent_survives_restart(tmp_path, pubkey, mint):
    path, token = str(tmp_path / "spent.db"), mint()
    first = Verifier({EPOCH: pubkey}, path)
    assert first.redeem(token)
    first.db.close()
    second = Verifier({EPOCH: pubkey}, path)
    assert not second.redeem(token)
    second.db.close()


def test_uncommitted_redemption_can_be_rolled_back(verifier, mint):
    token = mint()
    assert verifier.redeem(token, commit=False)
    verifier.db.rollback()
    assert verifier.redeem(token)                     # still spendable


def test_forgeries_rejected(verifier, mint):
    token = mint()
    assert not verifier.redeem(dict(token, nonce="00" * 32))
    assert not verifier.redeem(dict(token, sig=format(int(token["sig"], 16) ^ 1, "x")))
    assert not verifier.redeem(dict(token, epoch="other-epoch"))
    assert verifier.redeem(token)                     # the original is unharmed


def test_signature_plus_modulus_rejected(verifier, mint, pubkey):
    """sig + n verifies under plain modular exponentiation; refuse it."""
    token = mint()
    alias = format(int(token["sig"], 16) + int(pubkey["n"], 16), "x")
    assert not verifier.redeem(dict(token, sig=alias))


@pytest.mark.parametrize("bad", [
    None, "string", 7, [], {},
    {"epoch": EPOCH},
    {"epoch": EPOCH, "nonce": "zz" * 32, "sig": "1"},
    {"epoch": EPOCH, "nonce": "AB" * 32, "sig": "1"},      # uppercase
    {"epoch": EPOCH, "nonce": "ab" * 31, "sig": "1"},      # short
    {"epoch": EPOCH, "nonce": "ab" * 32, "sig": 5},
    {"epoch": EPOCH, "nonce": "ab" * 32, "sig": "0x1f"},
    {"epoch": EPOCH, "nonce": "ab" * 32, "sig": "-1"},
    {"epoch": EPOCH, "nonce": "ab" * 32, "sig": "0"},
    {"epoch": ["x"], "nonce": "ab" * 32, "sig": "1"},
    {"epoch": "../etc", "nonce": "ab" * 32, "sig": "1"},
])
def test_malformed_tokens_never_raise(verifier, bad):
    assert verifier.redeem(bad) is False


def test_expired_key_rejected(tmp_path, pubkey, mint):
    ring = {EPOCH: dict(pubkey, expires=1000)}
    v = Verifier(ring, str(tmp_path / "spent.db"))
    token = mint()
    assert not v.redeem(token, now=1000)
    assert v.redeem(token, now=999)
    v.db.close()


def test_quota_enforced_per_employee_and_epoch(tmp_path):
    iss = Issuer(str(tmp_path / "iss"), tokens_per_epoch=2)
    pub = iss.new_epoch_key("e1", key_size=2048)
    pub2 = iss.new_epoch_key("e2", key_size=2048)
    holder = Holder(pub)
    blinded = lambda: holder.prepare()[1]             # noqa: E731
    iss.sign_blinded("alice", "e1", blinded())
    iss.sign_blinded("alice", "e1", blinded())
    with pytest.raises(QuotaExceeded):
        iss.sign_blinded("alice", "e1", blinded())
    iss.sign_blinded("bob", "e1", blinded())          # other employee unaffected
    # Other epoch unaffected. A request must be blinded for that epoch's own
    # modulus, or it can fall outside the valid range.
    iss.sign_blinded("alice", "e2", Holder(pub2).prepare()[1])
    iss.close()


def test_issuer_rejects_bad_requests_without_charging_quota(tmp_path):
    iss = Issuer(str(tmp_path / "iss"), tokens_per_epoch=1)
    pub = iss.new_epoch_key("e1", key_size=2048)
    for bad in ("0", pub["n"], "nothex", "0x10", ""):
        with pytest.raises(ValueError):
            iss.sign_blinded("alice", "e1", bad)
    with pytest.raises(LookupError):
        iss.sign_blinded("alice", "no-such-epoch", "2")
    with pytest.raises(ValueError):
        iss.sign_blinded("alice", "../escape", "2")
    iss.sign_blinded("alice", "e1", Holder(pub).prepare()[1])   # quota intact
    iss.close()


def test_issuer_stores_no_employee_ids_and_protects_keys(tmp_path):
    keydir = tmp_path / "iss"
    iss = Issuer(str(keydir), tokens_per_epoch=3)
    pub = iss.new_epoch_key("e1", key_size=2048)
    iss.sign_blinded("EMP-SECRET-777", "e1", Holder(pub).prepare()[1])
    rows = iss.db.execute("SELECT emp_hash, epoch, n FROM quota").fetchall()
    assert len(rows) == 1 and rows[0][1:] == ("e1", 1)
    assert "EMP-SECRET-777" not in rows[0][0]
    for name in ("e1.pem", "quota.key"):
        assert stat.S_IMODE(os.stat(keydir / name).st_mode) == 0o600
    with pytest.raises(FileExistsError):              # never clobber an epoch key
        iss.new_epoch_key("e1", key_size=2048)
    with pytest.raises(ValueError):
        iss.new_epoch_key("weak", key_size=1024)
    iss.close()


def test_holder_detects_bad_issuer_signature(issuer, pubkey):
    holder = Holder(pubkey)
    state, blinded = holder.prepare()
    good = issuer.sign_blinded("EMP-2", EPOCH, blinded)
    with pytest.raises(ValueError):
        holder.finalize(state, format(int(good, 16) ^ 1, "x"))
    assert holder.finalize(state, good)["nonce"] == state["nonce"]


def test_blinded_request_reveals_nothing_about_token(pubkey):
    holder = Holder(pubkey)
    state, blinded = holder.prepare()
    assert state["nonce"] not in blinded
    assert holder.prepare()[1] != blinded


def test_token_is_a_standard_pss_signature(pubkey, mint):
    """Independent check with the cryptography library, bypassing this module."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    token = mint()
    n = int(pubkey["n"], 16)
    assert len(token["sig"]) == 2 * ((n.bit_length() + 7) // 8)
    rsa.RSAPublicNumbers(65537, n).public_key().verify(
        bytes.fromhex(token["sig"]), blindtoken._token_message(token["epoch"], token["nonce"]),
        padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())


def test_pss_encoding_matches_cryptography_library():
    """Sign our own EMSA-PSS encoding with a raw private-key operation and
    have the library accept it, across awkward modulus sizes."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    for bits in (2048, 2050, 2055, 2056):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits).private_numbers()
        n = priv.public_numbers.n
        for msg in (b"", b"abc", b"x" * 1000):
            em = blindtoken._emsa_pss_encode(msg, n.bit_length() - 1, b"\x07" * 48)
            # Key generation may return a modulus a bit shorter than asked.
            k = (n.bit_length() + 7) // 8
            sig = pow(int.from_bytes(em, "big"), priv.d, n).to_bytes(k, "big")
            assert blindtoken._pss_verify(n, 65537, msg, sig)
            assert not blindtoken._pss_verify(n, 65537, msg + b"!", sig)


def test_same_token_request_is_never_blinded_the_same_way(pubkey):
    assert len({Holder(pubkey).prepare()[1] for _ in range(5)}) == 5


@pytest.mark.parametrize("mutate", [
    lambda pk: pk.update(e=3),
    lambda pk: pk.update(e=True),
    lambda pk: pk.update(n="ff"),
    lambda pk: pk.update(n=format(int(pk["n"], 16) + 1, "x")),     # even modulus
    lambda pk: pk.update(epoch="bad epoch"),
    lambda pk: pk.update(expires="tomorrow"),
    lambda pk: pk.pop("n"),
])
def test_public_key_validation(pubkey, mutate):
    pk = dict(pubkey)
    mutate(pk)
    with pytest.raises(ValueError):
        parse_public_key(pk)


def test_load_keyring(tmp_path, pubkey):
    assert load_keyring(str(tmp_path / "missing.json")) == {}
    good = tmp_path / "good.json"
    good.write_text(json.dumps({EPOCH: pubkey}))
    assert load_keyring(str(good)) == {EPOCH: pubkey}
    for content in ("not json", "[]", json.dumps({"other": pubkey}),
                    json.dumps({EPOCH: {"epoch": EPOCH, "n": "ff", "e": 65537}})):
        bad = tmp_path / "bad.json"
        bad.write_text(content)
        with pytest.raises(ValueError):
            load_keyring(str(bad))
