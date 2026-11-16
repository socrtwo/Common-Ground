# Agent Verification — ICE-Sanctioned Anonymous Credentials

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
   against the epoch key and records nullifier = SHA-256(nonce).

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
