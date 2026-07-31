# SPDX-License-Identifier: AGPL-3.0-or-later
"""N5/N7/N8/N9 — pre-save capacity checks, ingest cleanup, staging cleanup
on site delete, tmp reaping, and 401 logging."""
import io
import os
import time
import uuid

import pytest

from conftest import make_site


def _auth(key):
    return {"Authorization": f"Bearer {key}"}


def test_chunk_refused_before_touching_disk_when_full(app, client, monkeypatch):
    import shutil as _shutil
    from collections import namedtuple
    _, key = make_site(app, require_e2ee=False)
    Usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(_shutil, "disk_usage", lambda p: Usage(100, 100, 0))

    upload_id = str(uuid.uuid4())
    r = client.post("/api/v1/backups/chunk", headers=_auth(key), data={
        "upload_id": upload_id, "chunk_index": "0", "total_chunks": "2",
        "chunk": (io.BytesIO(b"x" * 1024), "chunk"),
    })
    assert r.status_code == 507
    # The refusal happened BEFORE the bytes landed: no staging dir exists.
    staging = os.path.join(app.config["DATA_DIR"], "upload-chunks")
    assert not os.path.isdir(staging) or not any(
        upload_id in dirs for _, dirs, _ in os.walk(staging))


def test_upload_and_chunked_finalize_still_work(app, client):
    _, key = make_site(app, require_e2ee=False)
    # Single-shot.
    r = client.post("/api/v1/backups", headers=_auth(key), data={
        "scope": "full", "file": (io.BytesIO(b"a" * 100), "a.bin")})
    assert r.status_code == 201, r.get_json()

    # Chunked: 2 chunks then finalize.
    upload_id = str(uuid.uuid4())
    for i, blob in enumerate((b"hello-", b"world")):
        r = client.post("/api/v1/backups/chunk", headers=_auth(key), data={
            "upload_id": upload_id, "chunk_index": str(i), "total_chunks": "2",
            "chunk": (io.BytesIO(blob), "chunk")})
        assert r.status_code == 200, r.get_json()
    r = client.post("/api/v1/backups/finalize", headers=_auth(key), data={
        "upload_id": upload_id, "scope": "full", "filename": "h.bin",
        "total_chunks": "2"})
    assert r.status_code == 201, r.get_json()
    assert r.get_json()["backup"]["size"] == 11
    # This upload's staging dir cleaned up (empty site- parent may remain).
    assert not any(upload_id in dirs for _, dirs, _ in os.walk(
        os.path.join(app.config["DATA_DIR"], "upload-chunks")))


def test_ingest_failure_leaves_no_partial_blob(app):
    from app import storage
    from app.models import Site, db
    site_id, _ = make_site(app, encrypt_at_rest=True)
    with app.app_context():
        site = db.session.get(Site, site_id)
        src = os.path.join(storage.tmp_dir(app), "src.bin")
        with open(src, "wb") as f:
            f.write(b"data")

        def boom(*a, **kw):
            raise OSError("disk full")

        import app.storage as storage_mod
        orig = storage_mod.restenc.encrypt_file
        storage_mod.restenc.encrypt_file = boom
        try:
            with pytest.raises(OSError):
                storage.ingest(site, "full", src, "x.bin")
        finally:
            storage_mod.restenc.encrypt_file = orig
        # No .part, no .bin left behind in the site's storage dir.
        d = storage.site_dir(app, site_id)
        assert os.listdir(d) == []


def test_site_delete_removes_chunk_staging(app, logged_in, client):
    site_id, key = make_site(app, require_e2ee=False)
    upload_id = str(uuid.uuid4())
    r = client.post("/api/v1/backups/chunk", headers=_auth(key), data={
        "upload_id": upload_id, "chunk_index": "0", "total_chunks": "2",
        "chunk": (io.BytesIO(b"staged"), "chunk")})
    assert r.status_code == 200
    staging = os.path.join(app.config["DATA_DIR"], "upload-chunks", f"site-{site_id}")
    assert os.path.isdir(staging)

    r = logged_in.post(f"/sites/{site_id}/delete")
    assert r.status_code == 302
    assert not os.path.exists(staging)


def test_reaper_sweeps_stale_tmp_files(app):
    from app.api import _reap_stale_tmp
    from app import storage
    with app.app_context():
        tmp = storage.tmp_dir(app)
    old = os.path.join(tmp, "tspb-dl-stale.bin")
    fresh = os.path.join(tmp, "tspb-up-fresh.bin")
    other = os.path.join(tmp, "unrelated.txt")
    for p in (old, fresh, other):
        with open(p, "wb") as f:
            f.write(b"x")
    past = time.time() - 2 * 3600
    os.utime(old, (past, past))
    os.utime(other, (past, past))

    _reap_stale_tmp(tmp, 3600)
    assert not os.path.exists(old)          # stale transfer file: reaped
    assert os.path.exists(fresh)            # recent transfer file: kept
    assert os.path.exists(other)            # non-transfer file: untouched


def test_failed_api_auth_is_logged(app, client, caplog):
    import logging
    with caplog.at_level(logging.WARNING):
        r = client.get("/api/v1/ping", headers=_auth("tspb_wrongkey123"))
    assert r.status_code == 401
    assert any("API auth failed" in rec.message and "tspb_wro" in rec.message
               for rec in caplog.records)
    # Never the whole key.
    assert not any("tspb_wrongkey123" in rec.message for rec in caplog.records)


def test_remember_cookie_duration_is_short(app):
    from datetime import timedelta
    assert app.config["REMEMBER_COOKIE_DURATION"] <= timedelta(days=14)
