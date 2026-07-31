# SPDX-License-Identifier: AGPL-3.0-or-later
"""N2 — /register hardening (credentials-in-URL, admin pin, audit logging)
and the restore page's changed-endpoint re-confirmation flow."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from conftest import make_site


def _auth(key):
    return {"Authorization": f"Bearer {key}"}


def test_register_rejects_credentials_in_url(app, client):
    _, key = make_site(app)
    r = client.post("/api/v1/register", headers=_auth(key), json={
        "callback_url": "https://evil@portal.example.org",
        "restore_token": "tok", "restore_enabled": "1"})
    assert r.status_code == 400
    assert "credentials" in r.get_json()["error"]


def test_register_respects_admin_pinned_host(app, client, caplog):
    site_id, key = make_site(app, restore_url_pinned="portal.example.org")

    # Matching host: accepted.
    r = client.post("/api/v1/register", headers=_auth(key), json={
        "callback_url": "https://portal.example.org", "restore_token": "tok",
        "restore_enabled": "1"})
    assert r.status_code == 200

    # Any other host: refused, loudly.
    r = client.post("/api/v1/register", headers=_auth(key), json={
        "callback_url": "https://attacker.example.net", "restore_token": "tok",
        "restore_enabled": "1"})
    assert r.status_code == 403
    from app.models import Site, db
    with app.app_context():
        assert db.session.get(Site, site_id).restore_callback_url == "https://portal.example.org"


def test_reregistration_is_logged(app, client, caplog):
    import logging
    _, key = make_site(app)
    client.post("/api/v1/register", headers=_auth(key), json={
        "callback_url": "https://one.example.org", "restore_token": "tok",
        "restore_enabled": "1"})
    with caplog.at_level(logging.WARNING):
        client.post("/api/v1/register", headers=_auth(key), json={
            "callback_url": "https://two.example.org", "restore_token": "tok",
            "restore_enabled": "1"})
    assert any("re-registered" in rec.message for rec in caplog.records)


class _OkSite(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        payload = json.dumps({"ok": True, "message": "restored"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def _restore_fixture(app, callback_url):
    """Site registered for restore + one full backup; returns their ids."""
    import os
    from app import storage
    from app.models import Backup, Site, db
    site_id, key = make_site(app, restore_enabled=True)
    with app.app_context():
        site = db.session.get(Site, site_id)
        site.restore_callback_url = callback_url
        site.set_restore_token("secret-token")
        db.session.commit()
        d = storage.site_dir(app, site_id)
        with open(os.path.join(d, "blob.bin"), "wb") as f:
            f.write(b"backup-bytes")
        b = Backup(site_id=site_id, scope="full", original_name="site.tar.gz",
                   stored_name="blob.bin", size_bytes=12, stored_bytes=12)
        db.session.add(b)
        db.session.commit()
        return site_id, b.id


def test_unconfirmed_endpoint_requires_hostname_not_restore(app, logged_in):
    srv = HTTPServer(("127.0.0.1", 0), _OkSite)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    site_id, backup_id = _restore_fixture(app, url)

    # The page warns that the endpoint was never confirmed.
    page = logged_in.get(f"/backups/{backup_id}/restore")
    assert "verify before continuing".encode() in page.data.lower() or b"endpoint changed" in page.data.lower()

    # Typing RESTORE is not enough while unconfirmed.
    r = logged_in.post(f"/backups/{backup_id}/restore",
                       data={"private_key": "tspsk_x", "confirm": "restore"},
                       follow_redirects=False)
    assert r.status_code == 302
    from app.models import Site, db
    with app.app_context():
        site = db.session.get(Site, site_id)
        assert site.restore_url_acked is None
        assert site.restore_endpoint_changed

    # Typing the hostname confirms, records the ack, and the push proceeds.
    r = logged_in.post(f"/backups/{backup_id}/restore",
                       data={"private_key": "tspsk_x", "confirm": "127.0.0.1"},
                       follow_redirects=False)
    assert r.status_code == 302
    with app.app_context():
        site = db.session.get(Site, site_id)
        assert site.restore_url_acked
        assert not site.restore_endpoint_changed
    srv.shutdown()


def test_reregistered_url_re_triggers_confirmation(app, client, logged_in):
    srv = HTTPServer(("127.0.0.1", 0), _OkSite)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    site_id, backup_id = _restore_fixture(app, url)

    from app.models import Site, db
    with app.app_context():
        site = db.session.get(Site, site_id)
        site.ack_restore_endpoint()
        db.session.commit()
        key = site.issue_api_key()
        db.session.commit()
        assert not site.restore_endpoint_changed

    # Whoever holds the API key silently moves the endpoint...
    r = client.post("/api/v1/register", headers=_auth(key), json={
        "callback_url": "https://moved.example.org", "restore_token": "secret-token",
        "restore_enabled": "1"})
    assert r.status_code == 200

    # ...and the restore flow demands re-confirmation again.
    with app.app_context():
        assert db.session.get(Site, site_id).restore_endpoint_changed
    r = logged_in.post(f"/backups/{backup_id}/restore",
                       data={"private_key": "tspsk_x", "confirm": "restore"})
    with app.app_context():
        site = db.session.get(Site, site_id)
        assert site.restore_endpoint_changed  # still unconfirmed, push refused
    srv.shutdown()
