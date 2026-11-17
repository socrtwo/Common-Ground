# Agent Verification — ICE-Sanctioned Anonymous Credentials

> **Status: proposal.** This document describes a design. Nothing in this
> repository implies that ICE or DHS has reviewed, endorsed, or agreed to it,
> and no agency issuer or agency key is included. The code implementing it is
> an unaudited prototype (see "Prototype versus production" below).

## Goal
ICE authorizes which employees may carry a "Verified ICE employee" badge,
while neither ICE nor the platform can link a badge to a person.

## Protocol (blind signatures, Privacy Pass architecture)
1. ICE publishes one RSA public key per epoch (quarterly) at a fixed
   agency URL; the platform pins it.
2. Agent authenticates to ICE's Issuer via PIV/SSO.
3. Agent's device creates token {epoch, random nonce}, blinds it, sends it.
4. Issuer checks quota (N tokens/employee/epoch), signs the blinded value,
   stores only a count.
5. Agent unblinds -> valid ICE signature on a token ICE never saw.
6. Agent redeems at platform after a random delay; platform verifies
   against the epoch key and records a nullifier (a hash of the token).

## Properties
- Agency control: no tokens without ICE authentication; ICE can end the
  program by not publishing keys.
- Unlinkability: holds even if ICE and the platform pool records
  (only timing metadata remains; mitigated by batch issuance + delay).
- Revocation: epoch expiry; separated employees cannot renew.
- Sybil limit: N tokens/epoch, single-use.

## Required operational rules
- Platform keeps no IP logs; supports Tor/onion access.
- Badge states only "ICE employee" — no component, rank, or office.
- Platform publicly discloses that it trusts the issuer's attestation.
- Production crypto: audited RFC 9474 (RSABSSA) library; Privacy Pass
  issuance per RFC 9578.

## Governance (MOU with ICE)
- Signed by ICE Office of Public Affairs + legal counsel.
- Defines eligible employee categories.
- Participation voluntary; ICE receives no data beyond issuance counts.
- Defines prohibited content (non-public operational info, PII, case details).

## Fallback issuers
If ICE declines: a neutral employment verifier (e.g., university ombuds) or
an employee union. Code is identical; only the published key changes.

---

## How the prototype implements it (`src/blindtoken.py`)

### Formats
Integers are lowercase hex strings with no `0x` prefix.

    public key   {"epoch": "2026-Q4", "n": "<hex>", "e": 65537, "expires": 1798761600}
    token        {"epoch": "2026-Q4", "nonce": "<64 hex chars>", "sig": "<hex>"}
    keyring.json {"2026-Q4": <public key>, ...}

`expires` is optional Unix time. Epoch names are 1-32 characters from
`A-Z a-z 0-9 . _ -`, starting with a letter or digit.

The signed message is `"common-ground/token/v1" || 0x00 || epoch || 0x00 ||
nonce`, hashed onto the modulus with a SHAKE-256 full-domain hash. The
nullifier is SHA-256 over the same message under a separate domain tag.

### Issuer
- Private keys and the quota secret are created owner-readable only (0600)
  and an epoch key is never overwritten.
- The quota table holds only `HMAC(secret, epoch || employee ID)` and a
  count. Without the secret, the table cannot be matched against a staff
  list.
- Quota is taken in a single SQL statement, so concurrent requests cannot
  exceed it, and is charged only when a signature is actually returned.
- The signing operation is blinded against timing leakage and its result is
  checked before release.

### Holder
- Verifies the unblinded signature before accepting it, so a faulty or
  dishonest issuer is caught before a token is spent.

### Verifier (the platform)
- Accepts only well-formed tokens: exact nonce length, `0 < sig < n`,
  exponent 65537, modulus of at least 2048 bits. Malformed input is
  rejected, never an error.
- Rejects tokens for unknown or expired epochs.
- Records the nullifier in the same database transaction that grants the
  badge.

### What a badge means on the site
- Redeeming a token stores only the epoch on the account.
- The badge is shown while that epoch's key is in `keyring.json` and has not
  passed its `expires` time. After that the account must redeem a token from
  a current epoch.
- Each post records whether its author's badge was valid when it was
  written. Posts made before verification are not badged retroactively, and
  earlier posts keep their badge after an epoch ends.

### Rotating epochs
1. The issuer generates the next epoch's key and publishes the public half.
2. The platform operator adds it to `keyring.json` (no restart needed).
3. When the old epoch should end, remove its entry, or let `expires` pass.

## Prototype versus production

| Area | Prototype | Production requirement |
| --- | --- | --- |
| Signature scheme | Textbook blind RSA with a full-domain hash | RFC 9474 RSABSSA from an audited library |
| Issuance protocol | Python method calls | Privacy Pass issuance, RFC 9576 / RFC 9578 |
| Arithmetic | Python integers (not constant-time) | Constant-time implementation, keys in an HSM |
| Issuer authentication | A caller-supplied employee ID | Agency PIV / SSO in front of the issuer |
| Key distribution | A local JSON file | Key fetched from the fixed agency URL and pinned |
| Review | None | Independent security audit |
