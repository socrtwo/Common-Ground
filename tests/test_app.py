import json
import sqlite3

import pytest

import app as forum
from conftest import ADMIN_KEY, EPOCH

BADGE = b"Verified ICE employee"


def query(application, sql, *params):
    conn = sqlite3.connect(application.config["DB"])
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def start_thread(b, title="A question", body="Some text"):
    resp = b.post("/new", {"title": title, "body": body})
    assert resp.status_code == 302, resp.data
    return resp.headers["Location"]


# ----------------------------------------------------------------- accounts
def test_home_page_and_security_headers(browser):
    resp = browser().get("/")
    assert resp.status_code == 200
    assert b"No conversations yet." in resp.data
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Cache-Control"] == "no-store"


def test_pages_use_no_inline_style_or_script(member):
    """The CSP forbids both, so any that creep in would silently break."""
    start_thread(member)
    for path in ("/", "/t/1", "/rules", "/modlog", "/login", "/verify", "/admin"):
        html = member.get(path).data.lower()
        assert b"<script" not in html and b"style=" not in html and b"<style" not in html


def test_static_stylesheet_served(browser):
    resp = browser().get("/static/style.css")
    assert resp.status_code == 200 and resp.mimetype == "text/css"


def test_join_shows_secret_once_and_stores_only_its_hash(application, browser):
    b = browser()
    resp = b.post("/join")
    secret = b.client.get_cookie("cg_secret").value
    assert secret.encode() in resp.data
    assert secret.encode() not in b.get("/").data
    (stored,) = query(application, "SELECT secret_hash FROM users")[0]
    assert stored == forum.sha256_hex(secret) != secret


def test_join_twice_keeps_existing_account(application, browser):
    b = browser()
    b.join()
    assert b.post("/join").status_code == 302
    assert query(application, "SELECT COUNT(*) FROM users") == [(1,)]


def test_login_logout_cycle(browser):
    a = browser()
    secret = a.join()
    other = browser()
    assert other.post("/login", {"secret": "wrong"}).status_code == 403
    assert other.post("/login", {"secret": secret}).status_code == 302
    assert b"Log out" in other.get("/").data
    assert other.post("/logout").status_code == 302
    assert b"Join anonymously" in other.get("/").data


def test_join_rate_cap(application, browser, clock):
    application.config["MAX_JOINS_PER_HOUR"] = 2
    browser().join()
    browser().join()
    assert browser().post("/join").status_code == 429
    clock.advance(3601)
    browser().join()


def test_cookies_are_hardened(application, browser):
    b = browser()
    b.join()
    for name in ("cg_secret", "cg_csrf"):
        cookie = b.client.get_cookie(name)
        assert cookie.http_only and cookie.same_site == "Strict" and not cookie.secure
    application.config["COOKIE_SECURE"] = True
    resp = application.test_client().get("/")
    assert "Secure" in resp.headers["Set-Cookie"]


# --------------------------------------------------------------------- CSRF
def test_post_without_csrf_token_rejected(application, browser):
    b = browser()
    assert b.client.post("/join").status_code == 400
    assert b.client.post("/join", data={"csrf": "guess"}).status_code == 400
    assert application.test_client().post("/join", data={"csrf": ""}).status_code == 400
    assert query(application, "SELECT COUNT(*) FROM users") == [(0,)]


def test_login_csrf_blocked(browser):
    """A cross-site form cannot sign a visitor into the attacker's account."""
    attacker_secret = browser().join()
    victim = browser()
    resp = victim.client.post("/login", data={"secret": attacker_secret})
    assert resp.status_code == 400
    assert victim.client.get_cookie("cg_secret") is None


# ------------------------------------------------------------------ posting
def test_new_account_must_wait_then_can_post(browser, clock):
    b = browser()
    b.join()
    resp = b.post("/new", {"title": "T", "body": "B"})
    assert resp.status_code == 429 and b"New accounts" in resp.data
    assert b'value="T"' in resp.data                  # draft is preserved
    clock.advance(61)
    assert start_thread(b, "T", "B") == "/t/1"


def test_thread_and_reply_flow(member, browser, clock):
    start_thread(member, "Why <b>this</b>?", "First <script>alert(1)</script>")
    other = browser()
    other.join()
    clock.advance(120)
    assert other.post("/t/1", {"body": "A reply"}).status_code == 302
    page = other.get("/t/1").data
    assert b"A reply" in page
    assert b"&lt;script&gt;" in page and b"<script>" not in page
    assert b"Why &lt;b&gt;this&lt;/b&gt;?" in page
    assert b"2 posts" in other.get("/").data
    assert other.get("/t/999").status_code == 404


def test_post_interval_enforced(member, clock):
    start_thread(member)
    resp = member.post("/t/1", {"body": "too soon"})
    assert resp.status_code == 429 and b"too soon" in resp.data
    clock.advance(31)
    assert member.post("/t/1", {"body": "later"}).status_code == 302


def test_validation(application, member, browser):
    assert member.post("/new", {"title": "   ", "body": "x"}).status_code == 400
    assert member.post("/new", {"title": "x", "body": "  "}).status_code == 400
    assert member.post("/new", {"title": "t" * 151, "body": "x"}).status_code == 400
    assert member.post("/new", {"title": "x", "body": "b" * 4001}).status_code == 400
    assert query(application, "SELECT COUNT(*) FROM threads") == [(0,)]
    # CRLF line breaks count once, as they do for the browser's maxlength.
    start_thread(member, "x\ny", "ab\r\n" * 1000 + "abcd")
    assert query(application, "SELECT title, LENGTH(body) FROM threads, posts") == [("x y", 3004)]
    assert browser().post("/new", {"title": "x", "body": "y"}).status_code == 403


def test_oversized_request_rejected(member):
    assert member.post("/new", {"title": "x", "body": "b" * 100_000}).status_code == 413


def test_index_pagination(application, member, clock):
    application.config["PAGE_SIZE"] = 2
    for i in range(3):
        start_thread(member, f"Topic {i}")
        clock.advance(60)
    first, second = member.get("/").data, member.get("/?page=2").data
    assert b"Topic 2" in first and b"Topic 1" in first and b"Topic 0" not in first
    assert b"Topic 0" in second and b"Topic 2" not in second
    assert member.get("/?page=junk").status_code == 200


# ---------------------------------------------------------------- reporting
def test_report_requires_account_valid_rule_and_live_post(application, member, browser):
    start_thread(member)
    assert browser().post("/report/1", {"rule": "1"}).status_code == 403
    assert member.post("/report/1", {"rule": "9"}).status_code == 400
    assert member.post("/report/1", {"rule": "x"}).status_code == 400
    assert member.post("/report/999", {"rule": "1"}).status_code == 404
    assert query(application, "SELECT COUNT(*) FROM reports") == [(0,)]


def test_duplicate_and_rapid_reports_are_contained(application, member, clock):
    start_thread(member)
    assert "m=reported" in member.post("/report/1", {"rule": "3"}).headers["Location"]
    assert "m=report-wait" in member.post("/report/1", {"rule": "3"}).headers["Location"]
    clock.advance(11)
    member.post("/report/1", {"rule": "1"})           # same account, same post
    assert query(application, "SELECT post_id, rule FROM reports") == [(1, 3)]
    assert b"Reported." in member.get("/t/1?m=reported").data
    assert b"<b>evil" not in member.get("/t/1?m=<b>evil").data


# --------------------------------------------------------------- moderation
def test_admin_requires_key(application, member):
    start_thread(member)
    assert member.get("/admin/post/1").status_code == 403
    assert member.post("/admin/post/1", {"action": "remove", "rule": "1"}).status_code == 403
    assert member.admin_login("wrong-key-wrong-key-wrong").status_code == 403
    assert member.admin_login("ключ").status_code == 403           # non-ASCII is not a crash
    member.client.set_cookie("cg_admin", ADMIN_KEY)                # raw key is not a session
    assert member.get("/admin/post/1").status_code == 403
    assert member.admin_login().status_code == 302
    assert member.get("/admin/post/1").status_code == 200
    assert member.client.get_cookie("cg_admin").value != ADMIN_KEY
    assert member.post("/admin/logout").status_code == 302
    assert member.get("/admin/post/1").status_code == 403


@pytest.mark.parametrize("key", [None, "", "short"])
def test_admin_disabled_without_strong_key(tmp_path, keyring_path, key):
    weak = forum.create_app({"TESTING": True, "DB": str(tmp_path / "w.db"),
                             "KEYRING": str(keyring_path), "ADMIN_KEY": key,
                             "COOKIE_SECURE": False})
    client = weak.test_client()
    assert b"disabled" in client.get("/admin").data
    csrf = client.get_cookie("cg_csrf").value
    assert client.post("/admin/login", data={"key": key or "", "csrf": csrf}).status_code == 403


def test_remove_post_cites_rule_mutes_and_logs(application, member, browser, clock):
    start_thread(member, "Topic", "offending text")
    reporter = browser()
    reporter.join()
    reporter.post("/report/1", {"rule": "3"})
    mod = browser()
    mod.admin_login()
    queue = mod.get("/admin").data
    assert b"Report queue (1)" in queue and b"offending text" in queue

    assert mod.post("/admin/post/1", {"action": "remove"}).status_code == 400
    assert mod.post("/admin/post/1", {"action": "remove", "rule": "0"}).status_code == 400
    assert mod.post("/admin/post/1", {"action": "remove", "rule": "3",
                                      "mute_days": "x"}).status_code == 400
    assert mod.post("/admin/post/1", {"action": "bogus"}).status_code == 400
    assert query(application, "SELECT COUNT(*) FROM modlog") == [(0,)]

    assert mod.post("/admin/post/1", {"action": "remove", "rule": "3",
                                      "mute_days": "99999"}).status_code == 302
    public = reporter.get("/t/1").data
    assert b"offending text" not in public and b"removed by moderator" in public
    assert b"offending text" in mod.get("/admin/post/1").data      # moderators still see it
    assert b"Report queue (0)" in mod.get("/admin").data
    log = reporter.get("/modlog").data
    assert b"removed post" in log and b"Rule 3: No threats, harassment, or slurs" in log
    assert b"muted 365d" in log                                    # clamped to the maximum
    assert reporter.post("/report/1", {"rule": "3"}).headers["Location"].endswith("m=report-gone")

    clock.advance(86400)
    resp = member.post("/t/1", {"body": "still here"})
    assert resp.status_code == 403 and b"muted until" in resp.data


def test_restore_unmute_and_dismiss_are_logged(application, member, browser, clock):
    start_thread(member, "Topic", "fine text")
    mod = browser()
    mod.admin_login()
    mod.post("/admin/post/1", {"action": "remove", "rule": "4", "mute_days": "7"})
    mod.post("/admin/post/1", {"action": "restore"})
    mod.post("/admin/post/1", {"action": "unmute"})
    mod.post("/admin/post/1", {"action": "unmute"})                # no-op, not logged twice
    assert b"fine text" in member.get("/t/1").data
    clock.advance(60)
    assert member.post("/t/1", {"body": "back"}).status_code == 302

    reporter = browser()
    reporter.join()
    reporter.post("/report/2", {"rule": "1"})
    mod.post("/admin/post/2", {"action": "dismiss"})
    assert b"Report queue (0)" in mod.get("/admin").data
    actions = [r[0] for r in query(application, "SELECT action FROM modlog ORDER BY id")]
    assert actions == ["removed post", "muted 7d", "restored post", "lifted mute",
                       "dismissed reports"]


def test_new_mute_never_shortens_existing_one(application, member, browser, clock):
    start_thread(member, "One", "a")
    clock.advance(60)
    member.post("/t/1", {"body": "b"})
    mod = browser()
    mod.admin_login()
    mod.post("/admin/post/1", {"action": "remove", "rule": "3", "mute_days": "30"})
    mod.post("/admin/post/2", {"action": "remove", "rule": "3", "mute_days": "1"})
    (until,) = query(application, "SELECT muted_until FROM users WHERE id=1")[0]
    assert until == clock.t + 30 * 86400


def test_thread_title_can_be_removed_only_via_opening_post(application, member, browser, clock):
    start_thread(member, "Name and address of someone", "body")
    clock.advance(60)
    member.post("/t/1", {"body": "reply"})
    mod = browser()
    mod.admin_login()
    mod.post("/admin/post/2", {"action": "hide_title", "rule": "1"})   # not the opener
    assert b"Name and address" in member.get("/").data
    mod.post("/admin/post/1", {"action": "hide_title", "rule": "1"})
    for path in ("/", "/t/1"):
        page = member.get(path).data
        assert b"Name and address" not in page and b"title removed" in page
    assert b"removed title" in member.get("/modlog").data
    mod.post("/admin/post/1", {"action": "restore_title"})
    assert b"Name and address" in member.get("/t/1").data


# ------------------------------------------------------------- verification
def test_badge_flow(application, member, browser, mint, clock):
    start_thread(member, "Before", "posted before verifying")
    token = mint()
    assert BADGE not in member.get("/").data
    resp = member.post("/verify", {"token": json.dumps(token)})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("m=verified")
    assert BADGE in member.get("/rules").data
    clock.advance(60)
    member.post("/t/1", {"body": "posted after verifying"})
    assert query(application, "SELECT agent FROM posts ORDER BY id") == [(0,), (1,)]
    assert b"agent participating" in browser().get("/").data

    # The same token cannot badge a second account.
    other = browser()
    other.join()
    assert other.post("/verify", {"token": json.dumps(token)}).status_code == 400
    assert BADGE not in other.get("/rules").data
    assert query(application, "SELECT COUNT(*) FROM spent") == [(1,)]


@pytest.mark.parametrize("payload", ["", "not json", "[]", "null", '"str"', "{}",
                                     '{"epoch": "test-epoch"}'])
def test_verify_rejects_garbage_without_crashing(member, payload):
    assert member.post("/verify", {"token": payload}).status_code == 400


def test_verify_requires_account(browser, mint):
    assert browser().post("/verify", {"token": json.dumps(mint())}).status_code == 302


def test_badge_lapses_when_epoch_key_is_retired(application, member, mint, keyring_path, clock):
    member.post("/verify", {"token": json.dumps(mint())})
    start_thread(member, "While verified", "text")
    keyring_path.write_text("{}")                     # platform drops the epoch
    assert BADGE not in member.get("/rules").data
    clock.advance(60)
    member.post("/t/1", {"body": "after lapse"})
    # Earlier posts keep the badge they were made under; new ones get none.
    assert query(application, "SELECT agent FROM posts ORDER BY id") == [(1,), (0,)]
    assert b"Agent verification" in member.get("/").data          # may re-verify


def test_badge_lapses_when_key_expires(application, member, mint, keyring_path, pubkey):
    member.post("/verify", {"token": json.dumps(mint())})
    assert BADGE in member.get("/rules").data
    keyring_path.write_text(json.dumps({EPOCH: dict(pubkey, expires=1)}))
    assert BADGE not in member.get("/rules").data
    assert member.post("/verify", {"token": json.dumps(mint())}).status_code == 400


def test_corrupt_keyring_fails_closed(member, mint, keyring_path):
    keyring_path.write_text("{ not json")
    assert member.get("/").status_code == 200
    assert member.post("/verify", {"token": json.dumps(mint())}).status_code == 400


# ----------------------------------------------------------------- database
def test_refuses_database_from_other_schema_version(tmp_path, keyring_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, handle TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(RuntimeError, match="schema"):
        forum.create_app({"DB": str(path), "KEYRING": str(keyring_path)})


def test_no_ip_address_is_stored(application, member, browser):
    start_thread(member)
    browser().get("/", environ_base={"REMOTE_ADDR": "203.0.113.77"})
    member.post("/t/1", {"body": "x"}, environ_base={"REMOTE_ADDR": "203.0.113.77"})
    conn = sqlite3.connect(application.config["DB"])
    dump = "\n".join(conn.iterdump())
    conn.close()
    assert "203.0.113" not in dump


# ------------------------------------------------------- moderator identities
def team_app(tmp_path, keyring_path, mod_keys, admin_key=None, **extra):
    return forum.create_app({"TESTING": True, "DB": str(tmp_path / "team.db"),
                             "KEYRING": str(keyring_path), "ADMIN_KEY": admin_key,
                             "MOD_KEYS": mod_keys, "COOKIE_SECURE": False, **extra,
                             "NEW_ACCOUNT_WAIT": 0})


def client_for(application):
    client = application.test_client()
    client.get("/")
    csrf = client.get_cookie("cg_csrf").value
    return client, (lambda path, **data: client.post(path, data={**data, "csrf": csrf}))


def test_each_moderator_key_is_named_in_the_public_log(tmp_path, keyring_path, clock):
    keys = "agent-side=agent-key-0123456789, community=community-key-012345"
    application = team_app(tmp_path, keyring_path, keys)
    member, post = client_for(application)
    post("/join")
    post("/new", title="One", body="first")
    clock.advance(60)
    post("/t/1", body="second")

    for key, pid in (("agent-key-0123456789", 1), ("community-key-012345", 2)):
        mod, mod_post = client_for(application)
        assert mod_post("/admin/login", key=key).status_code == 302
        assert mod_post(f"/admin/post/{pid}", action="remove", rule="3").status_code == 302
    assert query(application, "SELECT moderator FROM modlog ORDER BY id") == [
        ("agent-side",), ("community",)]
    log = member.get("/modlog").data
    assert b"(by agent-side)" in log and b"(by community)" in log


def test_moderator_session_cannot_be_relabelled(tmp_path, keyring_path):
    keys = "alpha=alpha-key-0123456789ab,beta=beta-key-0123456789abc"
    application = team_app(tmp_path, keyring_path, keys)
    mod, post = client_for(application)
    post("/admin/login", key="alpha-key-0123456789ab")
    label, _, mac = mod.get_cookie("cg_admin").value.partition(":")
    assert label == "alpha" and b"Admin (alpha)" in mod.get("/").data
    mod.set_cookie("cg_admin", f"beta:{mac}")
    assert b"Admin login" in mod.get("/admin").data
    mod.set_cookie("cg_admin", f"nobody:{mac}")
    assert b"Admin login" in mod.get("/admin").data


def test_bad_moderator_entries_are_ignored(tmp_path, keyring_path):
    keys = "ok=ok-key-0123456789abcdef\nweak=short, bad label=key-0123456789abcdef, nokey"
    application = team_app(tmp_path, keyring_path, keys, admin_key="legacy-key-0123456789")
    with application.test_request_context("/"):
        assert sorted(forum.moderators()) == ["moderator", "ok"]
    _, post = client_for(application)
    assert post("/admin/login", key="short").status_code == 403
    assert post("/admin/login", key="legacy-key-0123456789").status_code == 302


# --------------------------------------------------------------------- purge
def test_purge_erases_content_permanently(application, member, browser, clock):
    start_thread(member, "Someone's home address", "their street and number")
    mod = browser()
    mod.admin_login()
    mod.post("/admin/post/1", {"action": "purge"})                 # not removed yet: no-op
    mod.post("/admin/post/1", {"action": "purge_title"})
    assert query(application, "SELECT body, purged FROM posts") == [("their street and number", 0)]

    mod.post("/admin/post/1", {"action": "remove", "rule": "1"})
    mod.post("/admin/post/1", {"action": "hide_title", "rule": "1"})
    mod.post("/admin/post/1", {"action": "purge"})
    mod.post("/admin/post/1", {"action": "purge_title"})
    assert query(application, "SELECT body, purged FROM posts") == [("", 1)]
    assert query(application, "SELECT title, title_hidden FROM threads") == [("", 1)]

    mod.post("/admin/post/1", {"action": "restore"})               # nothing left to restore
    mod.post("/admin/post/1", {"action": "restore_title"})
    assert query(application, "SELECT hidden FROM posts") == [(1,)]
    assert query(application, "SELECT title_hidden FROM threads") == [(1,)]
    for page in (member.get("/t/1").data, mod.get("/admin/post/1").data, member.get("/").data):
        assert b"street" not in page and b"home address" not in page
    assert b"permanently erased" in member.get("/t/1").data
    actions = [r[0] for r in query(application, "SELECT action FROM modlog ORDER BY id")]
    assert actions == ["removed post", "removed title", "purged post content", "purged title"]


# ---------------------------------------------------------- thread pagination
def test_thread_pagination_and_reply_lands_on_last_page(application, member, clock):
    application.config["PAGE_SIZE"] = 2
    start_thread(member, "Long thread", "post 0")
    for i in range(1, 4):
        clock.advance(60)
        resp = member.post("/t/1", {"body": f"post {i}"})
    assert resp.headers["Location"] == "/t/1?page=2#end"
    first, second = member.get("/t/1").data, member.get("/t/1?page=2").data
    assert b"post 0" in first and b"post 1" in first and b"post 2" not in first
    assert b"post 2" in second and b"post 3" in second and b"post 0" not in second
    assert b'href="/t/1?page=2"' in first and b'href="/t/1"' in second
    assert b"No posts on this page" in member.get("/t/1?page=9").data
    clock.advance(60)
    member.post("/t/1", {"body": "post 4"})
    assert b"post 4" in member.get("/t/1?page=3").data


# ----------------------------------------------------------------- migration
def test_schema_2_database_is_migrated_in_place(tmp_path, keyring_path):
    path = tmp_path / "v2.db"
    conn = sqlite3.connect(path)
    v2 = forum.SCHEMA.replace(",\n  purged INTEGER NOT NULL DEFAULT 0)", ")").replace(
        ",\n  moderator TEXT NOT NULL DEFAULT '')", ")")
    assert "purged INTEGER" not in v2 and "moderator TEXT" not in v2
    conn.executescript(v2)
    conn.execute("INSERT INTO modlog(action,target,reason,created) "
                 "VALUES('removed post','#1','r',1)")
    conn.execute("PRAGMA user_version=2")
    conn.commit()
    conn.close()
    application = forum.create_app({"TESTING": True, "DB": str(path),
                                    "KEYRING": str(keyring_path), "COOKIE_SECURE": False})
    assert query(application, "PRAGMA user_version") == [(3,)]
    assert query(application, "SELECT action, moderator FROM modlog") == [("removed post", "")]
    assert query(application, "SELECT COUNT(purged) FROM posts") == [(0,)]
    assert b"removed post" in application.test_client().get("/modlog").data


# ----------------------------------------------------------- moderator sides
SIDED = "a1@agent=agent-key-0123456789,c1@community=community-key-012345"


def test_agent_side_key_needs_a_valid_badge(tmp_path, keyring_path, mint, clock):
    application = team_app(tmp_path, keyring_path, SIDED)
    mod, post = client_for(application)
    post("/join")
    post("/new", title="T", body="text")
    assert post("/admin/login", key="agent-key-0123456789").status_code == 302
    assert mod.get("/admin").status_code == 403                    # no badge yet
    assert b"valid agent badge" in mod.get("/admin").data
    assert post("/admin/post/1", action="remove", rule="3").status_code == 403
    assert query(application, "SELECT COUNT(*) FROM modlog") == [(0,)]

    post("/verify", token=json.dumps(mint()))
    assert mod.get("/admin").status_code == 200
    assert post("/admin/post/1", action="remove", rule="3").status_code == 302
    assert query(application, "SELECT moderator FROM modlog") == [("a1 (agent side)",)]

    keyring_path.write_text("{}")                                  # badge lapses
    assert mod.get("/admin/post/1").status_code == 403


def test_community_side_key_is_labelled_and_needs_no_badge(tmp_path, keyring_path):
    application = team_app(tmp_path, keyring_path, SIDED)
    member, post = client_for(application)
    post("/join")
    post("/new", title="T", body="text")
    mod, mod_post = client_for(application)
    mod_post("/admin/login", key="community-key-012345")
    assert b"Admin (c1 (community side))" in mod.get("/").data
    mod_post("/admin/post/1", action="remove", rule="3")
    assert b"(by c1 (community side))" in member.get("/modlog").data


@pytest.mark.parametrize("keys,admin_key,enabled", [
    (SIDED, None, ["a1", "c1"]),
    (SIDED, "legacy-key-0123456789", ["a1", "c1"]),               # unsided key ignored
    ("a1@agent=agent-key-0123456789", None, []),                   # one side only
    ("c1@community=community-key-012345,c2@community=community-key-0123456", None, []),
    ("a1@agent=agent-key-0123456789,c1@community=short", None, []),
    ("plain=plain-key-0123456789ab", "legacy-key-0123456789", []),
])
def test_require_both_sides(tmp_path, keyring_path, keys, admin_key, enabled):
    application = team_app(tmp_path, keyring_path, keys, admin_key, REQUIRE_BOTH_SIDES=True)
    with application.test_request_context("/"):
        assert sorted(forum.moderators()) == enabled
    client, post = client_for(application)
    assert (b"disabled" in client.get("/admin").data) == (not enabled)
    if not enabled:
        assert post("/admin/login", key="agent-key-0123456789").status_code == 403


def test_invalid_side_is_rejected(tmp_path, keyring_path):
    application = team_app(tmp_path, keyring_path, "x@police=some-key-0123456789ab")
    with application.test_request_context("/"):
        assert forum.moderators() == {}


# ------------------------------------------------------------- purge scrubbing
def test_purged_text_is_gone_from_the_database_files(application, member, browser):
    secret_text = "ZQXJ-unique-marker-742-Elm-Street"
    start_thread(member, "Title " + secret_text, "Body " + secret_text)
    mod = browser()
    mod.admin_login()

    def on_disk():
        import glob
        return any(secret_text.encode() in open(f, "rb").read()
                   for f in glob.glob(application.config["DB"] + "*"))

    # A second, idle connection (another worker, say) keeps the journal file
    # alive, so only an explicit scrub can clear it.
    other = sqlite3.connect(application.config["DB"])
    other.execute("SELECT COUNT(*) FROM posts").fetchall()
    assert on_disk()
    mod.post("/admin/post/1", {"action": "remove", "rule": "1"})
    mod.post("/admin/post/1", {"action": "hide_title", "rule": "1"})
    assert on_disk()                                               # removal only hides
    mod.post("/admin/post/1", {"action": "purge"})
    mod.post("/admin/post/1", {"action": "purge_title"})
    assert not on_disk()
    other.close()
    assert b"purged post content" in member.get("/modlog").data    # the log survives
