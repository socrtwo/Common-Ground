import json

import pytest

import app as forum
from blindtoken import Holder, Issuer

EPOCH = "test-epoch"
ADMIN_KEY = "test-admin-key-0123456789"


@pytest.fixture(scope="session")
def issuer(tmp_path_factory):
    """One RSA key for the whole run; key generation dominates test time."""
    iss = Issuer(str(tmp_path_factory.mktemp("issuer")), tokens_per_epoch=10_000)
    iss.new_epoch_key(EPOCH, key_size=2048)
    yield iss
    iss.close()


@pytest.fixture(scope="session")
def pubkey(issuer):
    return issuer.public_key(EPOCH)


@pytest.fixture
def mint(issuer, pubkey):
    """Returns a function producing a fresh, valid, unspent token."""
    def _mint(employee="EMP-1"):
        holder = Holder(pubkey)
        state, blinded = holder.prepare()
        return holder.finalize(state, issuer.sign_blinded(employee, EPOCH, blinded))
    return _mint


@pytest.fixture
def keyring_path(tmp_path, pubkey):
    path = tmp_path / "keyring.json"
    path.write_text(json.dumps({EPOCH: pubkey}))
    return path


@pytest.fixture
def clock(monkeypatch):
    """Controllable replacement for the forum's wall clock."""
    class Clock:
        t = 1_800_000_000

        def advance(self, seconds):
            self.t += seconds

    c = Clock()
    monkeypatch.setattr(forum, "now", lambda: c.t)
    return c


@pytest.fixture
def application(tmp_path, keyring_path, clock):
    return forum.create_app({
        "TESTING": True,
        "DB": str(tmp_path / "forum.db"),
        "KEYRING": str(keyring_path),
        "ADMIN_KEY": ADMIN_KEY,
        "COOKIE_SECURE": False,
    })


class Browser:
    """Test client that behaves like a browser submitting the site's forms:
    it echoes the CSRF cookie back in every POST."""

    def __init__(self, application):
        self.client = application.test_client()
        self.client.get("/")                      # picks up the CSRF cookie

    def get(self, *args, **kwargs):
        return self.client.get(*args, **kwargs)

    def post(self, path, data=None, **kwargs):
        data = dict(data or {})
        data.setdefault("csrf", self.client.get_cookie("cg_csrf").value)
        return self.client.post(path, data=data, **kwargs)

    def join(self):
        resp = self.post("/join")
        assert resp.status_code == 200
        return self.client.get_cookie("cg_secret").value

    def admin_login(self, key=ADMIN_KEY):
        return self.post("/admin/login", {"key": key})


@pytest.fixture
def browser(application):
    """Factory: each call is an independent visitor with its own cookie jar."""
    return lambda: Browser(application)


@pytest.fixture
def member(browser, clock):
    """A joined visitor who is past the new-account wait."""
    b = browser()
    b.join()
    clock.advance(3600)
    return b
