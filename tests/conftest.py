# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared fixtures: an isolated app (fresh temp DATA_DIR + SQLite) per test."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ADMIN_PASSWORD = "test-password-123"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TSPB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("TSPB_DEBUG", "1")  # plain-HTTP cookies + http restore targets
    monkeypatch.setenv("TSPB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("TSPB_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("TSPB_ADMIN_PASSWORD", ADMIN_PASSWORD)
    from app import create_app
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def logged_in(client):
    r = client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD})
    assert r.status_code == 302
    return client


def make_site(app, **overrides):
    """Create a site inside an app context; returns (site_id, raw_api_key)."""
    from app.models import Site, db
    with app.app_context():
        site = Site(name=overrides.pop("name", "Test Site"), enabled=True)
        raw = site.issue_api_key()
        for k, v in overrides.items():
            setattr(site, k, v)
        db.session.add(site)
        db.session.commit()
        return site.id, raw
