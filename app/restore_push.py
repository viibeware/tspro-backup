# SPDX-License-Identifier: AGPL-3.0-or-later
"""Push a stored backup back into its live TS Pro site (remote restore).

The normal data flow is one-way: sites push backups *to* us. This module
is the deliberate exception — an out-of-band recovery path for when the
operator can no longer drive a restore from the site itself (corrupted
data, locked-out admin, an accidental IP/login lockout). The operator
triggers it from *this* console; we stream the stored archive back to the
site's inbound ``/api/v1/restore`` endpoints, which apply it.

Two independent secrets gate the operation, so neither alone is enough:

  * the **restore token** the site published (``X-Restore-Token``) — proves
    the request comes from the paired backup server;
  * the operator's **private key**, supplied at restore time — the site
    requires it to (a) decrypt the E2EE archive and (b) confirm it matches
    the public key the site has on file. We forward it untouched and never
    store it; decryption happens on the site, never here, so this server
    stays zero-knowledge.

We send exactly the bytes the site originally uploaded (the at-rest layer,
if any, is stripped by ``storage.open_for_download``). For E2EE sites that
is the ``TSPEPK01`` envelope; the site decrypts it with the private key.
"""
import os
import re
import uuid

from . import storage

# Match the upload side's default chunk size so a body-size-limited proxy
# (e.g. Cloudflare's 100 MiB cap) in front of the *site* can't reject the
# push. Overridable, but 90 MiB is a safe default.
_CHUNK_MB = int(os.environ.get("TSPB_RESTORE_CHUNK_MB", "90"))
_CHUNK_BYTES = _CHUNK_MB * 1024 * 1024


class RestorePushError(Exception):
    """Any failure pushing a restore to the site (network, auth, refusal)."""


def _clean_filename(name):
    """The multipart filename travels in an outbound header; CR/LF or other
    control characters in a (client-supplied) original_name would corrupt the
    request we build. Replace them, and quotes/backslashes, with '_'."""
    return re.sub(r'[\x00-\x1f\x7f"\\]', "_", name) or "backup.bin"


def _post(sess, url, *, headers, data, files=None, timeout):
    """One restore POST. Never follows redirects: requests would replay the
    X-Restore-Token header and the private_key form field to the redirect
    target — including a plain-http one — so a 3xx is always an error here.
    The https check runs per-request, not just on the stored base URL."""
    debug = os.environ.get("TSPB_DEBUG", "").lower() in ("1", "true", "yes")
    if not url.lower().startswith("https://") and not debug:
        raise RestorePushError(
            "refusing to push a restore over plain HTTP — the site's callback "
            "URL must be https")
    r = sess.post(url, headers=headers, data=data, files=files,
                  allow_redirects=False, timeout=(10, timeout))
    if 300 <= r.status_code < 400:
        raise RestorePushError(
            "site returned a redirect — fix the callback URL to the final "
            "https address (restore credentials are never re-sent to a "
            "redirect target)")
    return r


def _check(resp, what):
    if resp.status_code in (200, 201):
        try:
            return resp.json()
        except Exception:  # noqa: BLE001
            return {"ok": True}
    try:
        msg = resp.json().get("error") or resp.text
    except Exception:  # noqa: BLE001
        msg = resp.text
    if resp.status_code in (401, 403):
        raise RestorePushError(f"site rejected the restore credentials: {msg}")
    raise RestorePushError(f"site {what} failed (HTTP {resp.status_code}): {msg}")


def push_restore(app, site, backup, private_key, *, timeout=120):
    """Push ``backup`` back into ``site`` for a live restore.

    Returns the site's JSON result dict on success. Raises
    ``RestorePushError`` on any failure. ``private_key`` is forwarded to the
    site verbatim and never persisted or logged here.
    """
    import requests

    if backup.site_id != site.id:
        raise RestorePushError("backup does not belong to this site")
    if backup.scope != "full":
        raise RestorePushError("only full (whole-site) backups can be restored remotely")
    if not site.restore_ready:
        raise RestorePushError(
            "this site has not enabled remote restore — turn it on in the TS Pro "
            "backup target settings, then run a backup / test the connection so it "
            "re-registers with this server.")
    private_key = (private_key or "").strip()
    if not private_key:
        raise RestorePushError("the site's private key is required to decrypt and apply the restore")

    base = site.restore_callback_url.rstrip("/")
    # Refuse to send a restore (which carries the private key) over plain
    # HTTP unless we're explicitly in dev — the key and token must stay on TLS.
    debug = os.environ.get("TSPB_DEBUG", "").lower() in ("1", "true", "yes")
    if not base.lower().startswith("https://") and not debug:
        raise RestorePushError(
            "refusing to push a restore over plain HTTP — the site's callback URL "
            "must be https. (Set TSPB_DEBUG=1 only for local testing.)")

    token = site.restore_token
    if not token:
        raise RestorePushError("no restore token on file for this site; re-pair the site")
    headers = {"X-Restore-Token": token}
    filename = _clean_filename(backup.original_name or f"backup-{backup.id}.bin")
    sess = requests.Session()

    path, is_temp = storage.open_for_download(app, backup)
    try:
        size = os.path.getsize(path)
        if size > _CHUNK_BYTES:
            return _push_chunked(sess, base, headers, path, size, filename,
                                 backup.scope, private_key, timeout)
        return _push_single(sess, base, headers, path, filename,
                            backup.scope, private_key, timeout)
    except requests.Timeout as e:
        raise RestorePushError(
            "timed out waiting for the site — it may still be applying the "
            "restore; check the site before retrying") from e
    except requests.RequestException as e:
        raise RestorePushError(f"could not reach the site: {e}") from e
    finally:
        if is_temp:
            try:
                os.remove(path)
            except OSError:
                pass


def _push_single(sess, base, headers, path, filename, scope, private_key, timeout):
    with open(path, "rb") as fh:
        r = _post(
            sess, f"{base}/api/v1/restore",
            headers=headers,
            data={"scope": scope, "filename": filename, "private_key": private_key},
            files={"file": (filename, fh, "application/octet-stream")},
            timeout=timeout,
        )
    return _check(r, "restore")


def _push_chunked(sess, base, headers, path, size, filename, scope, private_key, timeout):
    upload_id = str(uuid.uuid4())
    total = (size + _CHUNK_BYTES - 1) // _CHUNK_BYTES
    with open(path, "rb") as fh:
        index = 0
        while True:
            block = fh.read(_CHUNK_BYTES)
            if not block:
                break
            r = _post(
                sess, f"{base}/api/v1/restore/chunk",
                headers=headers,
                data={"upload_id": upload_id, "chunk_index": index, "total_chunks": total},
                files={"chunk": ("chunk", block, "application/octet-stream")},
                timeout=timeout,
            )
            _check(r, "restore chunk")
            index += 1
    # Private key + apply happen only on finalize, not on every chunk.
    r = _post(
        sess, f"{base}/api/v1/restore/finalize",
        headers=headers,
        data={"upload_id": upload_id, "scope": scope, "filename": filename,
              "total_chunks": total, "private_key": private_key},
        timeout=timeout,
    )
    return _check(r, "restore finalize")
