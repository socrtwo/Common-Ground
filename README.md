# Common Ground

[![CI](https://github.com/socrtwo/Common-Ground/actions/workflows/ci.yml/badge.svg)](https://github.com/socrtwo/Common-Ground/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An anonymous dialogue forum between verified ICE employees and the public.

- **Join with one click.** A random handle plus a secret key; no email, phone,
  or IP address is stored.
- **Anonymous agent badge.** Agents earn a "Verified ICE employee" badge by
  redeeming an agency-issued, blind-signed token
  ([docs/VERIFICATION.md](docs/VERIFICATION.md)). The site cannot tell which
  employee a badge belongs to, and neither can the issuer.
- **Narrow, public moderation** ([docs/MODERATION.md](docs/MODERATION.md)).
  Five fixed rules, every removal must cite one, mutes are time-limited, and
  every moderator action appears in a public log.

## Status

**Prototype. Not for production use.**

- This is an independent project. It is not affiliated with, endorsed by, or
  operated by U.S. Immigration and Customs Enforcement or the Department of
  Homeland Security. The verification design is a proposal; this repository
  ships no agency issuer and no agency key.
- The credential code is textbook blind RSA written for clarity. It has not
  been audited. A real deployment must replace it with an audited RFC 9474
  implementation (see [docs/VERIFICATION.md](docs/VERIFICATION.md)).
- See [Known limitations](#known-limitations) before relying on any property
  described here.

## Quick start

Requires Python 3.9 or newer and SQLite 3.24 or newer. CI runs on Python 3.11,
3.13 and 3.14 (GitHub's hosted runners no longer provide 3.9).

```sh
git clone https://github.com/socrtwo/Common-Ground.git
cd Common-Ground
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cd src
ADMIN_KEY=$(python3 -c "import secrets;print(secrets.token_urlsafe(16))") python3 app.py
```

Open <http://127.0.0.1:5000>. To use the admin panel at `/admin`, choose the
`ADMIN_KEY` yourself (16 characters or more) so you know what to type. The
panel is disabled when neither `ADMIN_KEY` nor `CG_MOD_KEYS` is set.

### Termux (Android)

```sh
pkg install -y git python python-cryptography
git clone https://github.com/socrtwo/Common-Ground.git
cd Common-Ground && pip install flask
cd src && ADMIN_KEY=choose-16-or-more-chars python3 app.py
```

`scripts/termux-install.sh` does the same and then runs the protocol
walkthrough as a self-test.

`python-cryptography` is installed from the Termux package so that pip does
not try to compile it on the device.

### Try the agent badge

With no agency issuer, a stand-in script plays that role for local testing:

```sh
cd src
python3 make_demo_token.py     # writes keyring.json, prints one token
```

Join the forum, open **Agent verification**, and paste the token. Run the
script again for another token. `python3 demo_verification.py` walks through
the whole protocol (issue, redeem, replay, forgery, quota) on the console.

Never point a public site at a keyring produced by `make_demo_token.py`:
anyone who can read `demo_issuer/` can mint badges.

## Configuration

Set through environment variables.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADMIN_KEY` | unset | Single moderator password, shown in the mod log as `moderator`. Must be at least 16 characters. |
| `CG_MOD_KEYS` | unset | One key per moderator: `label=key` entries separated by commas or newlines, e.g. `agent-side=...,community=...`. Each key must be at least 16 characters. The label is public (it appears in the mod log), so use a role, not a name. |
| `CG_DB` | `commonground.db` | SQLite database path. |
| `CG_KEYRING` | `keyring.json` | Pinned issuer public keys, `{epoch: key}`. Re-read on each request, so keys rotate without a restart. |
| `CG_COOKIE_SECURE` | `1` under WSGI, `0` for `python3 app.py` | Send cookies with the `Secure` flag. Leave on for anything served over HTTPS. |
| `PORT` | `5000` | Port for the built-in development server. |

Rate limits and size limits (`POST_INTERVAL`, `NEW_ACCOUNT_WAIT`,
`MAX_JOINS_PER_HOUR`, `MAX_BODY_LEN`, ...) are in `DEFAULTS` at the top of
`src/app.py` and can be overridden through `create_app({...})`.

## Running behind a real server

`python3 app.py` starts Flask's development server on loopback only. For
anything else, use a WSGI server behind a TLS-terminating reverse proxy:

```sh
cd src && ADMIN_KEY=... gunicorn 'app:create_app()'
```

The application stores no IP addresses, but the layers around it will unless
told otherwise. The "no IP stored" promise holds only if you also:

- turn off access logging in the reverse proxy and the WSGI server
  (gunicorn logs none by default; nginx needs `access_log off;`),
- keep error logs free of client addresses,
- serve over HTTPS only, and
- ideally offer a Tor onion service.

## Tests

```sh
pip install -r requirements-dev.txt
pytest          # credential protocol and forum behaviour
ruff check .    # lint, including the flake8-bandit security rules
```

## Layout

```
src/app.py                Flask application (routes, moderation, rate limits)
scripts/termux-install.sh One-step install for Termux on Android
src/blindtoken.py         Issuer / Holder / Verifier for the blind-signed tokens
src/make_demo_token.py    TESTING ONLY stand-in for the agency issuer
src/demo_verification.py  Console walkthrough of the protocol
src/templates/, static/   Pages and stylesheet (no JavaScript)
tests/                    pytest suite
docs/MODERATION.md        Rules and moderation principles
docs/VERIFICATION.md      Credential protocol, properties, governance
```

## Security design

- Accounts are a 192-bit random secret; only its SHA-256 hash is stored.
- Cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` by default.
- Every form carries a CSRF token, including the login form (to stop a
  hostile page signing a visitor into an account someone else controls).
- A strict Content-Security-Policy (`default-src 'none'`, same-origin CSS
  only), `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.
- All output is HTML-escaped by Jinja; all SQL uses bound parameters.
- A token's nullifier and the badge it grants are committed in one
  transaction.
- A badge lasts only while the epoch key it was redeemed under is in the
  keyring and unexpired. Posts keep the badge state they were written under.

## Known limitations

- **Unaudited cryptography**, as stated above.
- **Weak Sybil resistance.** Accounts are free and anonymous by design. The
  per-account post interval, new-account delay, and site-wide join cap slow
  abuse but do not stop a determined attacker, and the join cap can itself be
  exhausted to block sign-ups for a while.
- **Moderator identity is only as good as key handling.** With `CG_MOD_KEYS`
  the mod log names the key that acted, but nothing stops moderators sharing
  a key, and nothing in the code requires that both sides be represented.
  The policy's two-sided team remains an operating commitment.
- **Removed content stays in the database** until a moderator purges it.
  Removal hides a post so it can be restored; purging erases the text for
  good. SQLite may keep erased bytes in free pages until the file is
  vacuumed, and backups keep whatever they captured.
- **Timing correlation.** If the issuer and the platform pool their logs,
  issuance and redemption times can still narrow down who holds a badge;
  see the mitigations in [docs/VERIFICATION.md](docs/VERIFICATION.md).
- **SQLite and a single process.** Fine for a prototype; not built for load.
- **Minimal migrations.** Schema 2 databases are upgraded in place on
  start-up. Anything older is refused rather than guessed at.

## Contributing

Issues and pull requests are welcome. Please run `pytest` and `ruff check .`
first, and add a test for any behaviour you change. Report security problems
privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Paul D Pruitt
