"""
Common Ground - anonymous dialogue between verified ICE employees and the public.

Run:   ADMIN_KEY=<16+ chars> python3 app.py      ->  http://127.0.0.1:5000
       (or CG_MOD_KEYS="label@agent=key,label@community=key", one per moderator)
WSGI:  gunicorn 'app:create_app()'

- No email, phone, or IP is stored. Accounts are a random handle + secret key.
- Agents get a "Verified ICE employee" badge by redeeming a blind-signed token
  (see blindtoken.py); the server cannot tell which employee it came from.
- Admins remove posts and mute accounts; every action goes to a public log.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time

from flask import (
    Blueprint,
    Flask,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    url_for,
)
from markupsafe import Markup

from blindtoken import Verifier, key_is_active, load_keyring

SCHEMA_VERSION = 3
# Statements that bring a database from the keyed version to the next one.
MIGRATIONS = {
    2: ["ALTER TABLE posts ADD COLUMN purged INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE modlog ADD COLUMN moderator TEXT NOT NULL DEFAULT ''"],
}
MOD_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,23}")
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  handle TEXT NOT NULL UNIQUE,
  secret_hash TEXT NOT NULL UNIQUE,
  agent_epoch TEXT,                         -- epoch of the redeemed credential
  muted_until INTEGER NOT NULL DEFAULT 0,
  last_post INTEGER NOT NULL DEFAULT 0,
  last_report INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS threads(
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id),
  agent INTEGER NOT NULL DEFAULT 0,         -- author's badge was valid when posted
  created INTEGER NOT NULL,
  bumped INTEGER NOT NULL,                  -- time of the latest post
  title_hidden INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS posts(
  id INTEGER PRIMARY KEY,
  thread_id INTEGER NOT NULL REFERENCES threads(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL,
  agent INTEGER NOT NULL DEFAULT 0,         -- author's badge was valid when posted
  created INTEGER NOT NULL,
  hidden INTEGER NOT NULL DEFAULT 0,
  purged INTEGER NOT NULL DEFAULT 0);        -- body erased; cannot be restored
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY,
  post_id INTEGER NOT NULL REFERENCES posts(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  rule INTEGER NOT NULL,
  created INTEGER NOT NULL,
  resolved INTEGER NOT NULL DEFAULT 0,
  UNIQUE(post_id, user_id));
CREATE TABLE IF NOT EXISTS modlog(
  id INTEGER PRIMARY KEY,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  reason TEXT NOT NULL,
  created INTEGER NOT NULL,
  moderator TEXT NOT NULL DEFAULT '');      -- public label of the acting moderator
CREATE INDEX IF NOT EXISTS users_created ON users(created);
CREATE INDEX IF NOT EXISTS threads_bumped ON threads(bumped);
CREATE INDEX IF NOT EXISTS posts_thread ON posts(thread_id, id);
CREATE INDEX IF NOT EXISTS reports_open ON reports(resolved, post_id);
"""

# (short label, full text). Keep the full text in sync with docs/MODERATION.md.
RULES = [
    ("No doxxing",
     "No doxxing: never post names, photos, addresses, or identifying details of anyone."),
    ("No operational information",
     "No operational information: no planned actions, locations, or case specifics."),
    ("No threats, harassment, or slurs",
     "No threats, harassment, or slurs."),
    ("Argue with ideas, not people",
     "Argue with ideas, not people. Good-faith disagreement is welcome."),
    ("No false agent claims",
     "Do not claim to be an agent without the verified badge."),
]

ADJECTIVES = ("quiet steady candid patient frank open plain level civil honest calm "
              "earnest fair gentle humble mindful sincere thoughtful careful direct "
              "curious mellow sturdy modest").split()
NOUNS = ("river cedar harbor bridge lantern meadow compass anchor ridge prairie "
         "orchard canyon beacon willow summit hollow garden trail delta grove "
         "mesa harvest ember tide").split()

# Fixed notices selectable with ?m=<code>; never reflect free text from the URL.
NOTICES = {
    "reported": "Reported. A moderator will review it.",
    "report-wait": "Please wait a few seconds between reports.",
    "report-gone": "That post is no longer available to report.",
    "verified": "Badge added. It appears on posts you make from now on.",
    "logged-out": "Logged out.",
}

DEFAULTS = {
    "POST_INTERVAL": 30,          # seconds between posts per account
    "REPORT_INTERVAL": 10,        # seconds between reports per account
    "NEW_ACCOUNT_WAIT": 60,       # seconds before a new account may post
    "MAX_JOINS_PER_HOUR": 120,    # site-wide cap on new accounts; 0 disables
    "MAX_BODY_LEN": 4000,
    "MAX_TITLE_LEN": 150,
    "MAX_MUTE_DAYS": 365,
    "PAGE_SIZE": 50,
    "MIN_ADMIN_KEY_LEN": 16,
    "MAX_CONTENT_LENGTH": 64 * 1024,
}

COOKIE_MAX_AGE = 3600 * 24 * 365
CSP = ("default-src 'none'; style-src 'self'; form-action 'self'; "
       "base-uri 'none'; frame-ancestors 'none'")

bp = Blueprint("forum", __name__)


# ------------------------------------------------------------------ database
def init_db(path: str) -> None:
    conn = sqlite3.connect(path)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        populated = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone()
        while populated and version in MIGRATIONS:
            for statement in MIGRATIONS[version]:
                conn.execute(statement)
            version += 1
            conn.execute(f"PRAGMA user_version={version}")
            conn.commit()
        if populated and version != SCHEMA_VERSION:
            raise RuntimeError(
                f"{path} uses database schema {version}; this code needs "
                f"{SCHEMA_VERSION} and has no migration from it. Move the old "
                f"file aside and restart.")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        conn.execute(Verifier.SCHEMA)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        conn.commit()
    finally:
        conn.close()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
        # Overwrite deleted or replaced content with zeros instead of leaving
        # it in free space inside the file.
        g.db.execute("PRAGMA secure_delete=ON")
    return g.db


@bp.teardown_app_request
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


# ------------------------------------------------------------------- helpers
def now() -> int:
    return int(time.time())


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def same(a: str, b: str) -> bool:
    """Constant-time string comparison that tolerates non-ASCII input."""
    return hmac.compare_digest(a.encode(), b.encode())


def fmt_time(t: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t))


def cfg(name: str):
    return current_app.config[name]


def current_user():
    if "user" not in g:
        secret = request.cookies.get("cg_secret")
        g.user = get_db().execute(
            "SELECT * FROM users WHERE secret_hash=?", (sha256_hex(secret),)
        ).fetchone() if secret else None
    return g.user


def keyring() -> dict:
    """Pinned issuer keys, re-read per request so rotation needs no restart.
    A malformed file fails closed: no key is trusted and badges lapse."""
    if "keyring" not in g:
        try:
            g.keyring = load_keyring(cfg("KEYRING"))
        except (ValueError, OSError) as ex:
            current_app.logger.error("Ignoring unusable keyring %s: %s", cfg("KEYRING"), ex)
            g.keyring = {}
    return g.keyring


def badge_active(user) -> bool:
    """A badge lasts only as long as the epoch key it was redeemed under."""
    if not user or not user["agent_epoch"]:
        return False
    pk = keyring().get(user["agent_epoch"])
    return pk is not None and key_is_active(pk)


SIDES = ("agent", "community")


def parse_mod_keys(text: str | None) -> tuple[dict, dict, list]:
    """Parse CG_MOD_KEYS: 'label=key' or 'label@side=key' entries separated
    by commas or newlines, side being 'agent' or 'community'.
    Returns ({label: key}, {label: side or ''}, [rejected-entry descriptions])."""
    keys, sides, bad = {}, {}, []
    for entry in re.split(r"[,\n]", text or ""):
        entry = entry.strip()
        if not entry:
            continue
        name, sep, key = entry.partition("=")
        label, at, side = name.strip().partition("@")
        if not sep or not MOD_LABEL_RE.fullmatch(label):
            bad.append("an entry without a valid label")
        elif at and side not in SIDES:
            bad.append(f"{label!r}: side must be 'agent' or 'community'")
        elif label in keys:
            bad.append(f"duplicate label {label!r}")
        else:
            keys[label], sides[label] = key.strip(), side
    return keys, sides, bad


def usable_moderators(config) -> tuple[dict, dict, list]:
    """Apply the key rules to the configuration.
    Returns ({label: key}, {label: side}, [warnings for the operator])."""
    keys, sides, warnings = parse_mod_keys(config["MOD_KEYS"])
    warnings = [f"CG_MOD_KEYS: ignoring {problem}." for problem in warnings]
    if config["ADMIN_KEY"] and "moderator" not in keys:
        keys["moderator"], sides["moderator"] = config["ADMIN_KEY"], ""
    short = sorted(k for k in keys if len(keys[k]) < config["MIN_ADMIN_KEY_LEN"])
    if short:
        warnings.append(f"Ignoring moderator key(s) shorter than "
                        f"{config['MIN_ADMIN_KEY_LEN']} characters: {', '.join(short)}.")
    if config["REQUIRE_BOTH_SIDES"]:
        unassigned = sorted(k for k in keys if not sides[k])
        if unassigned:
            warnings.append("CG_REQUIRE_BOTH_SIDES: ignoring key(s) with no side: "
                            f"{', '.join(unassigned)}.")
        short += unassigned
    keys = {k: v for k, v in keys.items() if k not in short}
    if config["REQUIRE_BOTH_SIDES"] and {sides[k] for k in keys} != set(SIDES):
        warnings.append("CG_REQUIRE_BOTH_SIDES: moderation is disabled until an agent-side "
                        "and a community-side key are both configured.")
        keys = {}
    elif not keys:
        warnings.append("No usable ADMIN_KEY or CG_MOD_KEYS; admin panel disabled.")
    return keys, {k: sides[k] for k in keys}, warnings


def moderators() -> dict:
    """{public label: key} for every usable moderator key. ADMIN_KEY is the
    single-key shorthand and logs as 'moderator'; CG_MOD_KEYS gives each
    moderator their own key so the public log shows who acted."""
    if "moderators" not in g:
        g.moderators, g.mod_sides, _ = usable_moderators(current_app.config)
    return g.moderators


def moderator_side(label: str | None) -> str:
    moderators()
    return g.mod_sides.get(label, "")


def moderator_name() -> str:
    """How the acting moderator appears in the public log."""
    label = current_moderator()
    side = moderator_side(label)
    return f"{label} ({side} side)" if side else (label or "")


def moderator_block() -> str | None:
    """An agent-side key is honoured only from an account whose badge is
    currently valid, so 'agent side' in the log means a verified employee."""
    if moderator_side(current_moderator()) == "agent" and not badge_active(current_user()):
        return ("This is an agent-side moderator key. Log in to a forum account "
                "with a valid agent badge to use it.")
    return None


def admin_token(label: str) -> str:
    """Admin session cookie for one moderator. Derived from the key so the
    key itself is never stored in a browser."""
    mac = hmac.new(moderators()[label].encode(),
                   b"common-ground/admin-session/v2\x00" + label.encode(), hashlib.sha256)
    return f"{label}:{mac.hexdigest()}"


def current_moderator() -> str | None:
    """Public label of the moderator making this request, if any."""
    if "moderator" not in g:
        cookie = request.cookies.get("cg_admin", "")
        label = cookie.partition(":")[0]
        g.moderator = (label if label in moderators() and same(cookie, admin_token(label))
                       else None)
    return g.moderator


def is_admin() -> bool:
    return current_moderator() is not None


def require_admin() -> None:
    if not is_admin():
        abort(403)
    if moderator_block():
        abort(403, moderator_block())


def set_cookie(resp, name: str, value: str, max_age: int | None = COOKIE_MAX_AGE):
    resp.set_cookie(name, value, max_age=max_age, httponly=True, samesite="Strict",
                    secure=cfg("COOKIE_SECURE"))
    return resp


def clear_cookie(resp, name: str):
    resp.delete_cookie(name, httponly=True, samesite="Strict", secure=cfg("COOKIE_SECURE"))
    return resp


def rule_from_form() -> int | None:
    """1-based rule number from the submitted form, or None if invalid."""
    try:
        rule = int(request.form.get("rule", ""))
    except ValueError:
        return None
    return rule if 1 <= rule <= len(RULES) else None


def rule_label(rule: int) -> str:
    return f"Rule {rule}: {RULES[rule - 1][0]}"


def log_mod(action: str, target: str, reason: str) -> None:
    """Append to the public moderation log (caller commits)."""
    get_db().execute(
        "INSERT INTO modlog(action,target,reason,created,moderator) VALUES(?,?,?,?,?)",
        (action, target, reason, now(), moderator_name()))


def page_number() -> int:
    try:
        return max(1, min(int(request.args.get("page", "1")), 100000))
    except ValueError:
        return 1


# ----------------------------------------------------------- request plumbing
@bp.before_app_request
def csrf_protect():
    """Double-submit CSRF token. SameSite=Strict already keeps the account
    cookie off cross-site POSTs; this also stops login CSRF, where a hostile
    page signs the visitor into an account the attacker holds the key to."""
    cookie = request.cookies.get("cg_csrf", "")
    if request.method == "POST":
        if not cookie or not same(cookie, request.form.get("csrf", "")):
            abort(400, "This form has expired or cookies are disabled. "
                       "Go back, reload the page and try again.")
    g.csrf = cookie or secrets.token_urlsafe(24)


@bp.after_app_request
def finish_response(resp):
    csrf = g.get("csrf")
    if csrf and request.cookies.get("cg_csrf") != csrf:
        set_cookie(resp, "cg_csrf", csrf)
    resp.headers.setdefault("Content-Security-Policy", CSP)
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    if request.endpoint != "static":
        # Pages can show a secret key or reflect the viewer's account.
        resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.app_context_processor
def template_context():
    user = current_user()
    return {
        "user": user,
        "user_is_agent": badge_active(user),
        "admin": is_admin(),
        "moderator": moderator_name(),
        "rules": RULES,
        "notice": NOTICES.get(request.args.get("m", "")),
        "csrf_field": Markup('<input type="hidden" name="csrf" value="{}">').format(
            g.get("csrf", "")),
    }


# ------------------------------------------------------------------- posting
def post_block(user) -> tuple[str, int] | None:
    """Why this account may not post right now, as (message, HTTP status)."""
    if not user:
        return "Join or log in first.", 403
    t = now()
    if user["muted_until"] > t:
        return f"This account is muted until {fmt_time(user['muted_until'])}.", 403
    wait = user["created"] + cfg("NEW_ACCOUNT_WAIT") - t
    if wait > 0:
        return f"New accounts can post after {wait} more seconds.", 429
    wait = user["last_post"] + cfg("POST_INTERVAL") - t
    if wait > 0:
        return f"Please wait {wait} more seconds between posts.", 429
    return None


def clean_body(raw: str) -> str:
    # Browsers submit CRLF but count a line break as one character for
    # maxlength, so normalise before measuring.
    return raw.replace("\r\n", "\n").replace("\r", "\n").strip()


def body_error(body: str) -> str | None:
    if not body:
        return "Text is required."
    if len(body) > cfg("MAX_BODY_LEN"):
        return f"Posts are limited to {cfg('MAX_BODY_LEN')} characters."
    return None


def claim_post_slot(user) -> bool:
    """Atomically take this account's posting slot; False if a concurrent
    request got there first. Leaves the transaction open for the caller."""
    t = now()
    cur = get_db().execute("UPDATE users SET last_post=? WHERE id=? AND last_post<=?",
                           (t, user["id"], t - cfg("POST_INTERVAL")))
    return cur.rowcount == 1


def insert_post(user, thread_id: int, body: str) -> None:
    t = now()
    db = get_db()
    db.execute("INSERT INTO posts(thread_id,user_id,body,agent,created) VALUES(?,?,?,?,?)",
               (thread_id, user["id"], body, int(badge_active(user)), t))
    db.execute("UPDATE threads SET bumped=? WHERE id=?", (t, thread_id))


# -------------------------------------------------------------------- routes
def render_index(msg=None, status=200, title="", body=""):
    size, page = cfg("PAGE_SIZE"), page_number()
    rows = get_db().execute(
        """SELECT t.id, t.title, t.title_hidden, t.agent, u.handle,
             (SELECT COUNT(*) FROM posts p WHERE p.thread_id=t.id AND p.hidden=0) AS n,
             (SELECT MAX(p.agent) FROM posts p WHERE p.thread_id=t.id AND p.hidden=0) AS has_agent
           FROM threads t JOIN users u ON u.id=t.user_id
           ORDER BY t.bumped DESC, t.id DESC LIMIT ? OFFSET ?""",
        (size + 1, (page - 1) * size)).fetchall()
    return render_template("index.html", threads=rows[:size], page=page,
                           has_next=len(rows) > size, msg=msg,
                           draft_title=title, draft_body=body), status


@bp.get("/")
def index():
    return render_index()


@bp.post("/new")
def new_thread():
    user = current_user()
    title = " ".join(request.form.get("title", "").split())
    body = clean_body(request.form.get("body", ""))
    block = post_block(user)
    if block:
        return render_index(block[0], block[1], title, body)
    err = body_error(body)
    if not title:
        err = "A title is required."
    elif len(title) > cfg("MAX_TITLE_LEN"):
        err = f"Titles are limited to {cfg('MAX_TITLE_LEN')} characters."
    if err:
        return render_index(err, 400, title, body)
    db = get_db()
    if not claim_post_slot(user):
        db.rollback()
        return render_index("Please wait between posts.", 429, title, body)
    t = now()
    cur = db.execute("INSERT INTO threads(title,user_id,agent,created,bumped) VALUES(?,?,?,?,?)",
                     (title, user["id"], int(badge_active(user)), t, t))
    insert_post(user, cur.lastrowid, body)
    db.commit()
    return redirect(url_for("forum.thread", tid=cur.lastrowid))


@bp.route("/t/<int:tid>", methods=["GET", "POST"])
def thread(tid):
    db = get_db()
    t = db.execute("SELECT * FROM threads WHERE id=?", (tid,)).fetchone()
    if not t:
        abort(404)
    msg, status, draft = None, 200, ""
    if request.method == "POST":
        user = current_user()
        draft = clean_body(request.form.get("body", ""))
        block = post_block(user)
        if block:
            msg, status = block
        elif body_error(draft):
            msg, status = body_error(draft), 400
        elif not claim_post_slot(user):
            db.rollback()
            msg, status = "Please wait between posts.", 429
        else:
            insert_post(user, tid, draft)
            db.commit()
            return redirect(url_for("forum.thread", tid=tid, page=last_page(tid)) + "#end")
    size, page = cfg("PAGE_SIZE"), page_number()
    posts = db.execute(
        """SELECT p.*, u.handle FROM posts p JOIN users u ON u.id=p.user_id
           WHERE p.thread_id=? ORDER BY p.id LIMIT ? OFFSET ?""",
        (tid, size + 1, (page - 1) * size)).fetchall()
    return render_template("thread.html", t=t, posts=posts[:size], page=page,
                           has_next=len(posts) > size, msg=msg, draft=draft), status


def last_page(tid: int) -> int | None:
    """Page holding a thread's newest post; None for page 1 keeps URLs short."""
    n = get_db().execute("SELECT COUNT(*) FROM posts WHERE thread_id=?", (tid,)).fetchone()[0]
    pages = max(1, -(-n // cfg("PAGE_SIZE")))
    return pages if pages > 1 else None


@bp.post("/join")
def join():
    if current_user():
        return redirect(url_for("forum.index"))
    db = get_db()
    t = now()
    cap = cfg("MAX_JOINS_PER_HOUR")
    if cap and db.execute("SELECT COUNT(*) FROM users WHERE created>?",
                          (t - 3600,)).fetchone()[0] >= cap:
        return render_index("Too many new accounts right now. Please try again later.", 429)
    secret = secrets.token_urlsafe(24)
    for _ in range(20):
        handle = (secrets.choice(ADJECTIVES).title() + secrets.choice(NOUNS).title()
                  + str(secrets.randbelow(10000)))
        try:
            db.execute("INSERT INTO users(handle,secret_hash,created) VALUES(?,?,?)",
                       (handle, sha256_hex(secret), t))
            db.commit()
            break
        except sqlite3.IntegrityError:
            continue
    else:
        abort(503, "Could not allocate a handle. Please try again.")
    # Render the confirmation page as the new account.
    g.user = db.execute("SELECT * FROM users WHERE handle=?", (handle,)).fetchone()
    resp = current_app.make_response(
        render_template("joined.html", handle=handle, secret=secret,
                        wait=cfg("NEW_ACCOUNT_WAIT")))
    return set_cookie(resp, "cg_secret", secret)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        secret = request.form.get("secret", "").strip()
        if secret and get_db().execute("SELECT 1 FROM users WHERE secret_hash=?",
                                       (sha256_hex(secret),)).fetchone():
            return set_cookie(redirect(url_for("forum.index")), "cg_secret", secret)
        return render_template("login.html", msg="Unknown key."), 403
    return render_template("login.html")


@bp.post("/logout")
def logout():
    return clear_cookie(redirect(url_for("forum.index", m="logged-out")), "cg_secret")


@bp.get("/rules")
def rules():
    return render_template("rules.html")


@bp.route("/verify", methods=["GET", "POST"])
def verify():
    user = current_user()
    if not user:
        return redirect(url_for("forum.index"))
    msg, status = None, 200
    if request.method == "POST":
        try:
            token = json.loads(request.form.get("token", ""))
        except ValueError:
            token = None
        db = get_db()
        # The nullifier and the badge are committed together, so a crash
        # cannot burn a token without granting what it paid for.
        if Verifier(keyring(), db).redeem(token, commit=False):
            db.execute("UPDATE users SET agent_epoch=? WHERE id=?", (token["epoch"], user["id"]))
            db.commit()
            return redirect(url_for("forum.index", m="verified"))
        db.rollback()
        msg, status = "Token rejected (malformed, invalid, expired, or already used).", 400
    return render_template("verify.html", msg=msg), status


@bp.post("/report/<int:pid>")
def report(pid):
    user = current_user()
    if not user:
        abort(403)
    rule = rule_from_form()
    if rule is None:
        abort(400)
    db = get_db()
    post = db.execute("SELECT thread_id, hidden FROM posts WHERE id=?", (pid,)).fetchone()
    if not post:
        abort(404)
    back = url_for("forum.thread", tid=post["thread_id"])
    if post["hidden"]:
        return redirect(f"{back}?m=report-gone")
    t = now()
    cur = db.execute("UPDATE users SET last_report=? WHERE id=? AND last_report<=?",
                     (t, user["id"], t - cfg("REPORT_INTERVAL")))
    if cur.rowcount != 1:
        db.rollback()
        return redirect(f"{back}?m=report-wait#p{pid}")
    # One report per account per post; repeats are silently ignored.
    db.execute("INSERT OR IGNORE INTO reports(post_id,user_id,rule,created) VALUES(?,?,?,?)",
               (pid, user["id"], rule, t))
    db.commit()
    return redirect(f"{back}?m=reported#p{pid}")


@bp.get("/modlog")
def modlog():
    size, page = cfg("PAGE_SIZE"), page_number()
    rows = get_db().execute("SELECT * FROM modlog ORDER BY id DESC LIMIT ? OFFSET ?",
                            (size + 1, (page - 1) * size)).fetchall()
    return render_template("modlog.html", rows=rows[:size], page=page,
                           has_next=len(rows) > size)


# --------------------------------------------------------------------- admin
@bp.get("/admin")
def admin():
    if not is_admin():
        return render_template("admin_login.html", enabled=bool(moderators()))
    if moderator_block():
        return render_template("admin_login.html", enabled=True, msg=moderator_block()), 403
    queue = get_db().execute(
        """SELECT p.*, u.handle, COUNT(*) AS n_reports,
                  GROUP_CONCAT(DISTINCT r.rule) AS rules_cited
           FROM reports r JOIN posts p ON p.id=r.post_id JOIN users u ON u.id=p.user_id
           WHERE r.resolved=0 GROUP BY p.id ORDER BY MIN(r.id)""").fetchall()
    return render_template("admin.html", queue=queue)


@bp.post("/admin/login")
def admin_login():
    supplied, label = request.form.get("key", ""), None
    for candidate, key in moderators().items():      # no early exit: check every key
        if same(supplied, key) and label is None:
            label = candidate
    if label is None:
        return render_template("admin_login.html", enabled=bool(moderators()),
                               msg="Wrong key."), 403
    # Session cookie: admin access ends when the browser closes.
    return set_cookie(redirect(url_for("forum.admin")), "cg_admin", admin_token(label),
                      max_age=None)


@bp.post("/admin/logout")
def admin_logout():
    return clear_cookie(redirect(url_for("forum.index")), "cg_admin")


@bp.route("/admin/post/<int:pid>", methods=["GET", "POST"])
def admin_post(pid):
    require_admin()
    db = get_db()
    p = db.execute(
        """SELECT p.*, u.handle, u.muted_until, t.title, t.title_hidden,
                  (SELECT MIN(id) FROM posts WHERE thread_id=p.thread_id) = p.id AS is_opener,
                  (SELECT COUNT(*) FROM reports r
                    WHERE r.post_id=p.id AND r.resolved=0) AS n_reports
           FROM posts p JOIN users u ON u.id=p.user_id JOIN threads t ON t.id=p.thread_id
           WHERE p.id=?""", (pid,)).fetchone()
    if not p:
        abort(404)
    if request.method == "POST":
        moderate(db, p)
        db.commit()
        if g.pop("scrub", False):
            scrub_database(db)
        return redirect(url_for("forum.admin_post", pid=pid))
    return render_template("admin_post.html", p=p, muted=p["muted_until"] > now(),
                           max_mute=cfg("MAX_MUTE_DAYS"))


def scrub_database(db) -> None:
    """After a purge, remove the erased text from the journal and from free
    pages too. Best effort: if other connections are busy the next purge (or
    a manual VACUUM) finishes the job. Backups are out of reach from here."""
    try:
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.execute("VACUUM")
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError as ex:
        current_app.logger.warning("Purge committed, but the database scrub was "
                                   "skipped (%s). Run VACUUM when the site is idle.", ex)


def moderate(db, p) -> None:
    """Apply one moderation action to post row p. Every state change is
    written to the public log; removals must cite a rule."""
    action = request.form.get("action", "")
    pid, target = p["id"], f"#{p['id']} by {p['handle']}"

    if action in ("remove", "hide_title"):
        rule = rule_from_form()
        if rule is None:
            abort(400, "Removal must cite a rule.")
        reason = rule_label(rule)
        if action == "remove" and not p["hidden"]:
            try:
                days = int(request.form.get("mute_days", "0") or 0)
            except ValueError:
                abort(400, "Mute length must be a whole number of days.")
            days = max(0, min(days, cfg("MAX_MUTE_DAYS")))
            db.execute("UPDATE posts SET hidden=1 WHERE id=?", (pid,))
            db.execute("UPDATE reports SET resolved=1 WHERE post_id=?", (pid,))
            log_mod("removed post", target, reason)
            if days:
                # MAX() so a new mute never shortens one already running.
                db.execute("UPDATE users SET muted_until=MAX(muted_until, ?) WHERE id=?",
                           (now() + days * 86400, p["user_id"]))
                log_mod(f"muted {days}d", p["handle"], reason)
        elif action == "hide_title" and p["is_opener"] and not p["title_hidden"]:
            db.execute("UPDATE threads SET title_hidden=1 WHERE id=?", (p["thread_id"],))
            log_mod("removed title", f"thread #{p['thread_id']} by {p['handle']}", reason)
    elif action == "restore" and p["hidden"] and not p["purged"]:
        db.execute("UPDATE posts SET hidden=0 WHERE id=?", (pid,))
        log_mod("restored post", target, "Reinstated after review")
    elif action == "restore_title" and p["is_opener"] and p["title_hidden"] and p["title"]:
        db.execute("UPDATE threads SET title_hidden=0 WHERE id=?", (p["thread_id"],))
        log_mod("restored title", f"thread #{p['thread_id']} by {p['handle']}",
                "Reinstated after review")
    elif action == "unmute" and p["muted_until"] > now():
        db.execute("UPDATE users SET muted_until=0 WHERE id=?", (p["user_id"],))
        log_mod("lifted mute", p["handle"], "Lifted after review")
    elif action == "dismiss" and p["n_reports"]:
        db.execute("UPDATE reports SET resolved=1 WHERE post_id=?", (pid,))
        log_mod("dismissed reports", f"on post {target}", "No rule violation found")
    elif action == "purge" and p["hidden"] and not p["purged"]:
        # Irreversible: the text is erased, not just hidden. For doxxing and
        # similar material that must not linger in the database.
        db.execute("UPDATE posts SET body='', purged=1 WHERE id=?", (pid,))
        log_mod("purged post content", target, "Erased permanently")
        g.scrub = True
    elif action == "purge_title" and p["is_opener"] and p["title_hidden"] and p["title"]:
        db.execute("UPDATE threads SET title='' WHERE id=?", (p["thread_id"],))
        log_mod("purged title", f"thread #{p['thread_id']} by {p['handle']}",
                "Erased permanently")
        g.scrub = True
    elif action not in ("remove", "hide_title", "restore", "restore_title",
                        "unmute", "dismiss", "purge", "purge_title"):
        abort(400)


# ------------------------------------------------------------------- factory
def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(DEFAULTS)
    app.config.update(
        DB=os.environ.get("CG_DB", "commonground.db"),
        KEYRING=os.environ.get("CG_KEYRING", "keyring.json"),
        ADMIN_KEY=os.environ.get("ADMIN_KEY"),
        MOD_KEYS=os.environ.get("CG_MOD_KEYS"),
        REQUIRE_BOTH_SIDES=os.environ.get("CG_REQUIRE_BOTH_SIDES") == "1",
        # Secure by default; only plain-HTTP local testing should turn it off.
        COOKIE_SECURE=os.environ.get("CG_COOKIE_SECURE", "1") != "0",
    )
    app.config.update(config or {})
    app.jinja_env.filters["ts"] = fmt_time
    app.register_blueprint(bp)
    init_db(app.config["DB"])

    for warning in usable_moderators(app.config)[2]:
        app.logger.warning(warning)
    return app


if __name__ == "__main__":
    # The development server's access log records client IPs; silence it.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    # It also speaks plain HTTP on loopback, where Secure cookies would not
    # be sent by every browser. Set CG_COOKIE_SECURE=1 to force them anyway.
    dev_app = create_app({"COOKIE_SECURE": os.environ.get("CG_COOKIE_SECURE") == "1"})
    port = int(os.environ.get("PORT", "5000"))
    print(f"Common Ground running at http://127.0.0.1:{port}  (Ctrl+C to stop)")
    dev_app.run(host="127.0.0.1", port=port)
