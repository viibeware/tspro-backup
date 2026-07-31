# SPDX-License-Identifier: AGPL-3.0-or-later
"""N4 — freshly issued API keys / private keys must never ride in the
session cookie, and the reveal must be strictly one-time."""
import base64
import re
import zlib


def _session_cookie_payloads(client):
    """Decoded plaintext of every session cookie the client holds."""
    out = []
    for cookie in client._cookies.values() if hasattr(client, "_cookies") else []:
        out.append(cookie.value)
    # Werkzeug ≥ 2.3 test client
    jar = getattr(client, "_cookies", None) or {}
    payloads = []
    for c in jar.values():
        val = c.value
        payloads.append(val)
        body = val.lstrip(".").split(".")[0]
        body += "=" * (-len(body) % 4)
        try:
            raw = base64.urlsafe_b64decode(body)
            if val.startswith("."):
                raw = zlib.decompress(raw)
            payloads.append(raw.decode("utf-8", "replace"))
        except Exception:
            pass
    return payloads


def test_create_site_reveals_once_and_cookie_is_clean(app, logged_in):
    r = logged_in.post("/sites/new", data={"name": "Reveal Test", "enabled": "1"},
                       follow_redirects=False)
    assert r.status_code == 302

    # The cookie set during the redirect must not contain secret material.
    for payload in _session_cookie_payloads(logged_in):
        assert "tspb_" not in payload
        assert "tspsk_" not in payload

    # First view: both secrets shown.
    page = logged_in.get("/sites")
    html = page.get_data(as_text=True)
    key = re.search(r"tspb_[A-Za-z0-9_\-]+", html)
    priv = re.search(r"tspsk_[A-Za-z0-9_\-]+", html)
    assert key and priv

    # Second view: gone for good.
    html2 = logged_in.get("/sites").get_data(as_text=True)
    assert key.group(0) not in html2
    assert "tspsk_" not in html2

    # And the server-side stash is empty.
    from app.models import OneTimeSecret
    with app.app_context():
        assert OneTimeSecret.query.count() == 0


def test_rotate_key_reveals_once_on_site_page(app, logged_in):
    from conftest import make_site
    site_id, _ = make_site(app)
    r = logged_in.post(f"/sites/{site_id}/rotate-key", follow_redirects=False)
    assert r.status_code == 302
    for payload in _session_cookie_payloads(logged_in):
        assert "tspb_" not in payload

    html = logged_in.get(f"/sites/{site_id}").get_data(as_text=True)
    assert re.search(r"tspb_[A-Za-z0-9_\-]+", html)
    html2 = logged_in.get(f"/sites/{site_id}").get_data(as_text=True)
    assert not re.search(r'id="new-key"', html2)


def test_stash_expires(app):
    from datetime import datetime, timedelta
    from app.models import OneTimeSecret, db
    with app.app_context():
        nonce = OneTimeSecret.stash(1, api_key="tspb_zzz")
        row = OneTimeSecret.query.filter_by(nonce=nonce).first()
        row.created_at = datetime.utcnow() - timedelta(minutes=16)
        db.session.commit()
        assert OneTimeSecret.pop(nonce) is None
