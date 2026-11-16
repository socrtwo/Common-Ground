# Common Ground

An anonymous dialogue forum between verified ICE employees and the public.

- Join with one click: random handle + secret key; no email, phone, or IP stored.
- Agents earn a "Verified ICE employee" badge with an agency-issued
  blind-signed token (docs/VERIFICATION.md). The site cannot tell which
  employee a badge belongs to.
- Narrow moderation (docs/MODERATION.md): five fixed rules, removals must
  cite a rule, time-limited mutes, every action in a public mod log.

## Run locally
    cd src
    ADMIN_KEY=$(python3 -c "import secrets;print(secrets.token_urlsafe(16))") python3 app.py
Open http://127.0.0.1:5000

## Try the agent badge
    python3 make_demo_token.py    # prints a token; paste it at /verify
