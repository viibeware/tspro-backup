# SPDX-License-Identifier: AGPL-3.0-or-later
"""Physical storage of backup archives + ingest orchestration.

Layout on disk::

    <DATA_DIR>/storage/site-<id>/<uuid>.bin

Each ``.bin`` is either the raw archive TS Pro uploaded, or — when
at-rest encryption is on for the site — that archive wrapped by
``app.restenc``. The ``Backup`` row records which, so download knows
whether to unwrap.
"""
import hashlib
import os
import uuid
from datetime import datetime

from flask import current_app

from . import pubkey, restenc
from .models import Backup, Setting, db


def _storage_root(app):
    root = os.path.join(app.config["DATA_DIR"], "storage")
    os.makedirs(root, exist_ok=True)
    return root


def tmp_dir(app):
    """A scratch dir for upload staging / at-rest decrypt temp files, kept on
    the data volume (not shared /tmp) so disk accounting is honest and any
    transient plaintext stays on the controlled, owner-only volume."""
    d = os.path.join(app.config["DATA_DIR"], "tmp")
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def site_dir(app, site_id):
    d = os.path.join(_storage_root(app), f"site-{site_id}")
    os.makedirs(d, exist_ok=True)
    return d


def stored_path(app, backup: Backup):
    return os.path.join(site_dir(app, backup.site_id), backup.stored_name)


def ingest(site, scope, src_temp_path, original_name, note=None):
    """Take a fully-received upload at ``src_temp_path`` and persist it.

    Computes the checksum / size of the original bytes, detects whether
    TS Pro already encrypted them, optionally wraps them in the at-rest
    cipher, writes the final blob, creates the ``Backup`` row, then runs
    retention for this (site, scope). Returns the committed ``Backup``.

    The caller owns ``src_temp_path`` and should unlink it afterwards.
    """
    app = current_app._get_current_object()
    settings = Setting.get()

    # Detect the client-side envelope by STRUCTURE (not just an 8-byte magic):
    # a well-formed TSPEPK01 public-key envelope, or a TSPENC01 passphrase one.
    is_e2ee_envelope = pubkey.file_is_well_formed_envelope(src_temp_path)
    client_encrypted = is_e2ee_envelope or restenc.file_is_well_formed(src_temp_path)
    # Record which site key a TSPEPK01 upload targets, so a later rotation
    # doesn't leave the operator guessing which private key restores it.
    e2ee_fp = site.e2ee_fingerprint if (is_e2ee_envelope and site.e2ee_public_key) else None

    # Hash + size in one pass over the source.
    h = hashlib.sha256()
    size = 0
    with open(src_temp_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)

    stored_name = uuid.uuid4().hex + ".bin"
    dest = os.path.join(site_dir(app, site.id), stored_name)

    # Write to a .part name and rename into place only when complete: a
    # worker killed mid-write (disk full, SIGKILL at the 600s timeout) then
    # leaves an obvious partial, never a plausible-looking .bin. On any
    # failure the partial is removed so a dead write can't linger and eat
    # the volume.
    part = dest + ".part"
    encrypt_at_rest = site.effective_encrypt_at_rest(settings)
    try:
        if encrypt_at_rest:
            passphrase = restenc.resolve_rest_passphrase(app)
            restenc.encrypt_file(src_temp_path, part, passphrase)
        else:
            # Move/copy the raw bytes into place.
            with open(src_temp_path, "rb") as src, open(part, "wb") as out:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
        os.replace(part, dest)
    except Exception:
        for stale in (part, dest):
            try:
                os.remove(stale)
            except OSError:
                pass
        raise

    stored_bytes = os.path.getsize(dest)
    # Stored blobs are (E2EE / at-rest) ciphertext, but keep them owner-only
    # rather than world-readable so a non-root local user can't read the vault.
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass

    backup = Backup(
        site_id=site.id,
        scope=scope,
        original_name=original_name,
        stored_name=stored_name,
        size_bytes=size,
        stored_bytes=stored_bytes,
        sha256=h.hexdigest(),
        encrypted_at_rest=encrypt_at_rest,
        client_encrypted=client_encrypted,
        e2ee_fingerprint=e2ee_fp,
        note=note,
        created_at=datetime.utcnow(),
    )
    db.session.add(backup)
    site.last_seen_at = datetime.utcnow()
    db.session.commit()

    from .retention import prune_site_scope
    prune_site_scope(site, scope)
    return backup


def open_for_download(app, backup: Backup):
    """Return (path, is_temp) for a path whose bytes are exactly what TS
    Pro uploaded. If the blob was encrypted at rest we decrypt it to a
    temp file the caller must unlink; otherwise we hand back the stored
    path directly (is_temp=False)."""
    path = stored_path(app, backup)
    if not backup.encrypted_at_rest:
        return path, False
    import tempfile
    passphrase = restenc.resolve_rest_passphrase(app)
    tmp = tempfile.NamedTemporaryFile(prefix="tspb-dl-", suffix=".bin",
                                      dir=tmp_dir(app), delete=False)
    tmp.close()
    restenc.decrypt_file(path, tmp.name, passphrase)
    return tmp.name, True


def delete_blob(app, backup: Backup):
    """Remove the on-disk blob for a backup (row deletion is the
    caller's job). Missing file is not an error."""
    try:
        os.remove(stored_path(app, backup))
    except OSError:
        pass
