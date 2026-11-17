# Security Policy

Common Ground is a prototype whose whole purpose is to protect the anonymity
of the people using it, so reports of weaknesses are especially welcome.

## Reporting a vulnerability

Please do not open a public issue for anything that could put users at risk.

1. Use GitHub's private vulnerability reporting for this repository
   (**Security → Report a vulnerability**) if it is enabled.
2. If it is not, open an issue that says only that you have a security report
   and how you can be reached. Do not include details.

Useful reports include: how to reproduce the problem, what an attacker gains,
and which commit you tested.

## In scope

- Anything that links an account, post, or badge to a person, a device, or an
  IP address.
- Anything that links a redeemed token to its issuance.
- Forging, replaying, or transferring an agent badge in ways the design does
  not intend.
- Bypassing moderation logging, authentication, CSRF protection, or output
  escaping.

## Already known

- The issuing and blinding code is hand-written, unaudited Python and must
  be replaced before any real deployment (see `docs/VERIFICATION.md`).
- The limits listed under "Known limitations" in the README.

## Supported versions

Only the current `main` branch.
