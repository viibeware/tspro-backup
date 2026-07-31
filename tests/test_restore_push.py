# SPDX-License-Identifier: AGPL-3.0-or-later
"""N1/N6/N11 — restore push must never follow redirects (the restore token
and private key would be replayed to the redirect target), must honor its
timeout, and must sanitize the outbound multipart filename."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from conftest import make_site


class _Recorder(BaseHTTPRequestHandler):
    """Answers 200 and records every request (the would-be exfil target)."""
    hits = None  # set per-server

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        self.server.hits.append((self.path, dict(self.headers), body))
        payload = json.dumps({"ok": True, "message": "restored"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class _Redirector(BaseHTTPRequestHandler):
    """302s every POST to the recorder — a hostile / misconfigured site."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        self.send_response(302)
        self.send_header("Location", self.server.redirect_to + self.path)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    srv.hits = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _make_backup(app, site_id, data=b"backup-bytes"):
    from app import storage
    from app.models import Backup, db
    import os
    with app.app_context():
        d = storage.site_dir(app, site_id)
        with open(os.path.join(d, "blob.bin"), "wb") as f:
            f.write(data)
        b = Backup(site_id=site_id, scope="full", original_name="site.tar.gz",
                   stored_name="blob.bin", size_bytes=len(data),
                   stored_bytes=len(data))
        db.session.add(b)
        db.session.commit()
        return b.id


def test_redirect_is_refused_and_leaks_nothing(app):
    from app import restore_push
    from app.models import Backup, Site, db

    target = _serve(_Recorder)
    redirector = _serve(_Redirector)
    redirector.redirect_to = f"http://127.0.0.1:{target.server_address[1]}"

    site_id, _ = make_site(app, restore_enabled=True)
    backup_id = _make_backup(app, site_id)
    with app.app_context():
        site = db.session.get(Site, site_id)
        site.restore_callback_url = f"http://127.0.0.1:{redirector.server_address[1]}"
        site.set_restore_token("secret-token")
        db.session.commit()
        backup = db.session.get(Backup, backup_id)

        with pytest.raises(restore_push.RestorePushError, match="redirect"):
            restore_push.push_restore(app, site, backup, "tspsk_private")

    # Not one byte — no token, no private key — reached the redirect target.
    assert target.hits == []
    target.shutdown()
    redirector.shutdown()


def test_https_required_outside_debug(app, monkeypatch):
    from app import restore_push
    from app.models import Backup, Site, db

    monkeypatch.setenv("TSPB_DEBUG", "0")
    site_id, _ = make_site(app, restore_enabled=True)
    backup_id = _make_backup(app, site_id)
    with app.app_context():
        site = db.session.get(Site, site_id)
        site.restore_callback_url = "http://example.org"
        site.set_restore_token("secret-token")
        db.session.commit()
        backup = db.session.get(Backup, backup_id)
        with pytest.raises(restore_push.RestorePushError, match="plain HTTP"):
            restore_push.push_restore(app, site, backup, "tspsk_private")


def test_outbound_filename_is_sanitized():
    from app.restore_push import _clean_filename
    assert _clean_filename("evil\r\nX-Injected: 1.bin") == "evil__X-Injected: 1.bin"
    assert _clean_filename('a"b\\c.bin') == "a_b_c.bin"
    assert _clean_filename("\x00\x1f") == "__"
    assert _clean_filename("") == "backup.bin"
    assert _clean_filename("normal-name.tar.gz") == "normal-name.tar.gz"


def test_push_uses_finite_timeouts(app):
    """The requests calls must carry (connect, read) timeouts, not None."""
    import inspect
    from app import restore_push
    src = inspect.getsource(restore_push)
    assert "timeout=None" not in src
    assert "allow_redirects=False" in src
