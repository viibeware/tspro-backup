# SPDX-License-Identifier: AGPL-3.0-or-later
"""Web console routes — dashboard, sites, backups, settings, account.

All gated by login. The console is the operator's view; TS Pro instances
never touch these routes (they use the ``/api/v1`` blueprint).
"""
import os
import shutil
from functools import wraps

from flask import (Blueprint, abort, current_app, flash, jsonify, redirect,
                   render_template, request, send_file, session, url_for)
from flask_login import current_user, login_required, login_user

from .crypto import encrypt
from .models import (SCOPE_LABELS, SCOPES, AdminUser, Backup, OneTimeSecret,
                     Setting, Site, db)
from . import storage

bp = Blueprint("main", __name__)


def admin_required(fn):
    """Gate a route to admin users. The settings + user-management
    endpoints are AJAX/JSON, so a denial returns 403 JSON rather than a
    redirect."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not getattr(current_user, "is_admin", lambda: False)():
            return jsonify(ok=False, error="Admin permission required"), 403
        return fn(*args, **kwargs)
    return wrapper


def admin_required_page(fn):
    """Like ``admin_required`` but for normal form-POST routes: a non-admin
    gets a flash + redirect instead of raw JSON. Backstops the UI, which
    already hides these controls from the limited 'user' role."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not getattr(current_user, "is_admin", lambda: False)():
            flash("That action requires an admin account.", "danger")
            return redirect(request.referrer or url_for("main.sites"))
        return fn(*args, **kwargs)
    return wrapper


def _int_or_none(val):
    val = (val or "").strip()
    if val == "":
        return None
    try:
        return max(0, int(val))
    except ValueError:
        return None


# ──────────────────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────────────────
@bp.route("/")
@login_required
def dashboard():
    sites = Site.query.order_by(Site.name).all()
    backups = Backup.query.all()
    total_bytes = sum(b.stored_bytes or 0 for b in backups)
    recent = (Backup.query.order_by(Backup.created_at.desc()).limit(10).all())
    by_scope = {s: 0 for s in SCOPES}
    for b in backups:
        by_scope[b.scope] = by_scope.get(b.scope, 0) + 1
    stats = {
        "sites": len(sites),
        "sites_enabled": sum(1 for s in sites if s.enabled),
        "backups": len(backups),
        "total_bytes": total_bytes,
        "by_scope": by_scope,
    }
    return render_template("dashboard.html", sites=sites, recent=recent,
                           stats=stats, scope_labels=SCOPE_LABELS)


# ──────────────────────────────────────────────────────────────────────
# Sites
# ──────────────────────────────────────────────────────────────────────
@bp.route("/sites")
@login_required
def sites():
    rows = Site.query.order_by(Site.name).all()
    settings = Setting.get()
    # One-time reveal: the session holds only a nonce; the secrets live
    # server-side and are destroyed on this first (and only) read.
    new_key = new_privkey = new_key_site = None
    session.pop("key_reveal_site", None)
    reveal = OneTimeSecret.pop(session.pop("key_reveal", None))
    if reveal:
        new_key_site, new_key, new_privkey = reveal
    # Fingerprint of the just-created/rotated site, for the reveal modal.
    new_site = next((s for s in rows if s.id == new_key_site), None) if new_key_site else None
    new_fingerprint = new_site.e2ee_fingerprint if new_site else None
    return render_template("sites.html", sites=rows, settings=settings,
                           new_key=new_key, new_privkey=new_privkey,
                           new_key_site=new_key_site, new_fingerprint=new_fingerprint)


@bp.route("/sites/new", methods=["GET", "POST"])
@login_required
def site_new():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Site name is required", "danger")
            return redirect(url_for("main.site_new"))
        site = Site(name=name, enabled=True)
        _apply_site_form(site)
        raw_key = site.issue_api_key()
        privkey = site.issue_keypair()
        db.session.add(site)
        db.session.commit()
        session["key_reveal"] = OneTimeSecret.stash(site.id, api_key=raw_key,
                                                    privkey=privkey)
        session["key_reveal_site"] = site.id
        flash(f"Site “{name}” created. Copy its API key and private key now — neither is shown again.", "success")
        return redirect(url_for("main.sites"))
    return render_template("site_edit.html", site=None, settings=Setting.get())


@bp.route("/sites/<int:site_id>", methods=["GET", "POST"])
@login_required
def site_edit(site_id):
    site = Site.query.get_or_404(site_id)
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Site name is required", "danger")
            return redirect(url_for("main.site_edit", site_id=site_id))
        site.name = name
        _apply_site_form(site)
        db.session.commit()
        flash("Site updated", "success")
        return redirect(url_for("main.site_edit", site_id=site_id))
    # Surface a freshly rotated key once, on this page (set by
    # site_rotate_key / site_rotate_keypair). Session holds only a nonce;
    # the one-shot pop destroys the server-side copy.
    new_key = None
    new_privkey = None
    if session.get("key_reveal_site") == site.id:
        session.pop("key_reveal_site", None)
        reveal = OneTimeSecret.pop(session.pop("key_reveal", None))
        if reveal:
            _, new_key, new_privkey = reveal
    new_fingerprint = site.e2ee_fingerprint if (new_key or new_privkey) else None
    return render_template("site_edit.html", site=site, settings=Setting.get(),
                           new_key=new_key, new_privkey=new_privkey,
                           new_fingerprint=new_fingerprint)


def _apply_site_form(site):
    site.enabled = bool(request.form.get("enabled"))
    site.keep_daily = _int_or_none(request.form.get("keep_daily"))
    site.keep_weekly = _int_or_none(request.form.get("keep_weekly"))
    site.keep_monthly = _int_or_none(request.form.get("keep_monthly"))
    site.keep_yearly = _int_or_none(request.form.get("keep_yearly"))
    # Encryption policy is a security control: only admins may set the per-site
    # require_e2ee / encrypt_at_rest overrides. A non-admin's form submission
    # leaves the existing values untouched, so they can't weaken (or strengthen)
    # a site's encryption posture below the admin-controlled server default.
    if current_user.is_admin():
        enc = request.form.get("encrypt_at_rest", "inherit")
        site.encrypt_at_rest = {"on": True, "off": False}.get(enc, None)
        e2ee = request.form.get("require_e2ee", "inherit")
        site.require_e2ee = {"on": True, "off": False}.get(e2ee, None)
        # Pin the restore callback host (admin-only, like the encryption
        # policy): while set, /register can't move restores to another host.
        pinned = (request.form.get("restore_url_pinned") or "").strip()
        if "://" in pinned:  # accept a pasted URL, keep only its host
            from urllib.parse import urlsplit
            pinned = urlsplit(pinned).hostname or ""
        site.restore_url_pinned = pinned.lower() or None


@bp.route("/sites/<int:site_id>/rotate-key", methods=["POST"])
@login_required
@admin_required_page
def site_rotate_key(site_id):
    site = Site.query.get_or_404(site_id)
    raw_key = site.issue_api_key()
    db.session.commit()
    session["key_reveal"] = OneTimeSecret.stash(site.id, api_key=raw_key)
    session["key_reveal_site"] = site.id
    flash("API key rotated. The previous key no longer works.", "success")
    return redirect(url_for("main.site_edit", site_id=site.id))


@bp.route("/sites/<int:site_id>/rotate-keypair", methods=["POST"])
@login_required
@admin_required_page
def site_rotate_keypair(site_id):
    site = Site.query.get_or_404(site_id)
    privkey = site.issue_keypair()
    db.session.commit()
    session["key_reveal"] = OneTimeSecret.stash(site.id, privkey=privkey)
    session["key_reveal_site"] = site.id
    flash("Encryption keypair rotated. New backups use the new key; keep the "
          "OLD private key to decrypt backups already stored.", "success")
    return redirect(url_for("main.site_edit", site_id=site.id))


@bp.route("/sites/<int:site_id>/ack-key", methods=["POST"])
@login_required
def site_ack_key(site_id):
    site = Site.query.get_or_404(site_id)
    site.e2ee_key_ack = True
    db.session.commit()
    flash("Got it — we'll stop reminding you about this site's private key.", "success")
    return redirect(url_for("main.site_edit", site_id=site.id))


@bp.route("/sites/<int:site_id>/delete", methods=["POST"])
@login_required
@admin_required_page
def site_delete(site_id):
    site = Site.query.get_or_404(site_id)
    app = current_app._get_current_object()
    for b in list(site.backups):
        storage.delete_blob(app, b)
    # Also drop any staged chunk uploads — deleting the rows/blobs alone
    # would leave those bytes on disk until the TTL reaper found them.
    shutil.rmtree(os.path.join(app.config["DATA_DIR"], "upload-chunks",
                               f"site-{site.id}"), ignore_errors=True)
    name = site.name
    db.session.delete(site)
    db.session.commit()
    flash(f"Site “{name}” and all its backups were deleted", "success")
    return redirect(url_for("main.sites"))


# ──────────────────────────────────────────────────────────────────────
# Backups
# ──────────────────────────────────────────────────────────────────────
@bp.route("/backups")
@login_required
def backups():
    q = Backup.query
    site_id = request.args.get("site", type=int)
    scope = request.args.get("scope")
    if site_id:
        q = q.filter_by(site_id=site_id)
    if scope in SCOPES:
        q = q.filter_by(scope=scope)
    rows = q.order_by(Backup.created_at.desc()).all()
    sites = Site.query.order_by(Site.name).all()
    return render_template("backups.html", backups=rows, sites=sites,
                           scope_labels=SCOPE_LABELS, sel_site=site_id, sel_scope=scope)


@bp.route("/backups/<int:backup_id>/download")
@login_required
def backup_download(backup_id):
    backup = Backup.query.get_or_404(backup_id)
    app = current_app._get_current_object()
    try:
        path, is_temp = storage.open_for_download(app, backup)
    except Exception as e:  # noqa: BLE001
        current_app.logger.error("download failed for backup %s: %s", backup_id, e)
        abort(500)
    resp = send_file(path, as_attachment=True, download_name=backup.original_name)
    if is_temp:
        @resp.call_on_close
        def _cleanup():
            try:
                os.remove(path)
            except OSError:
                pass
    return resp


@bp.route("/backups/<int:backup_id>/restore", methods=["GET", "POST"])
@login_required
@admin_required_page
def backup_restore(backup_id):
    """Push a stored backup back into its live site (out-of-band recovery).

    Destructive on the *site*: it overwrites the site's database, uploads and
    keys. Admin-only, and gated by an explicit typed confirmation plus the
    operator's private key (which the site uses to decrypt and to confirm the
    key matches what it has on file). The key is forwarded to the site and
    never stored or logged here.
    """
    backup = Backup.query.get_or_404(backup_id)
    site = backup.site
    app = current_app._get_current_object()
    if backup.scope != "full" or not site.restore_ready:
        flash("Remote restore isn't available for this backup. It must be a "
              "whole-site backup, and the site must have remote restore enabled "
              "and registered with this server.", "danger")
        return redirect(url_for("main.backups"))

    # The restore endpoint is malleable by whoever holds the site's API key
    # (POST /api/v1/register). If it changed since the operator last confirmed
    # it — or was never confirmed — demand they re-type the full hostname, not
    # just RESTORE, so a silently re-pointed URL can't phish the private key.
    endpoint_changed = site.restore_endpoint_changed
    expected_host = site.restore_host

    if request.method == "POST":
        private_key = (request.form.get("private_key") or "").strip()
        confirm = (request.form.get("confirm") or "").strip().lower()
        if endpoint_changed:
            if confirm != expected_host:
                flash("The restore endpoint changed since it was last confirmed — "
                      f"verify it out-of-band, then type its full hostname "
                      f"(“{expected_host}”) to confirm.", "danger")
                return redirect(url_for("main.backup_restore", backup_id=backup.id))
            site.ack_restore_endpoint()
            db.session.commit()
        elif confirm != "restore":
            flash("Type RESTORE to confirm overwriting the live site.", "danger")
            return redirect(url_for("main.backup_restore", backup_id=backup.id))
        if not private_key:
            flash("The site's private key is required to decrypt and apply the restore.", "danger")
            return redirect(url_for("main.backup_restore", backup_id=backup.id))
        from . import restore_push
        try:
            result = restore_push.push_restore(app, site, backup, private_key)
        except restore_push.RestorePushError as e:
            # Never include the private key in logs — push_restore doesn't echo it.
            current_app.logger.warning("remote restore to site %s failed: %s", site.id, e)
            flash(f"Remote restore failed: {e}", "danger")
            return redirect(url_for("main.backup_restore", backup_id=backup.id))
        finally:
            private_key = None
        msg = (result or {}).get("message") or "the site accepted the restore."
        flash(f"Remote restore pushed — {msg} The site is applying the backup and "
              "recycling its workers; give it a moment, then sign in there.", "success")
        return redirect(url_for("main.backups"))

    return render_template("backup_restore.html", backup=backup, site=site,
                           endpoint_changed=endpoint_changed,
                           expected_host=expected_host)


@bp.route("/backups/<int:backup_id>/delete", methods=["POST"])
@login_required
def backup_delete(backup_id):
    backup = Backup.query.get_or_404(backup_id)
    app = current_app._get_current_object()
    storage.delete_blob(app, backup)
    db.session.delete(backup)
    db.session.commit()
    flash("Backup deleted", "success")
    return redirect(request.referrer or url_for("main.backups"))


# ──────────────────────────────────────────────────────────────────────
# Settings modal endpoints (AJAX/JSON) — server config + user management
# ──────────────────────────────────────────────────────────────────────
@bp.route("/settings", methods=["POST"])
@login_required
@admin_required
def settings():
    s = Setting.get()
    s.turnstile_enabled = bool(request.form.get("turnstile_enabled"))
    s.turnstile_site_key = (request.form.get("turnstile_site_key") or "").strip() or None
    secret = (request.form.get("turnstile_secret_key") or "").strip()
    if secret:
        s.turnstile_secret_key_enc = encrypt(secret)
    elif request.form.get("clear_turnstile_secret"):
        s.turnstile_secret_key_enc = None

    s.require_e2ee = bool(request.form.get("require_e2ee"))
    s.encrypt_at_rest = bool(request.form.get("encrypt_at_rest"))
    s.keep_daily = _int_or_none(request.form.get("keep_daily")) or 0
    s.keep_weekly = _int_or_none(request.form.get("keep_weekly")) or 0
    s.keep_monthly = _int_or_none(request.form.get("keep_monthly")) or 0
    s.keep_yearly = _int_or_none(request.form.get("keep_yearly")) or 0
    db.session.commit()
    return jsonify(ok=True, message="Server settings saved")


@bp.route("/account", methods=["POST"])
@login_required
def account():
    """Change the signed-in user's own password. Available to every role."""
    cur = request.form.get("current_password") or ""
    new = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""
    if not current_user.check_password(cur):
        return jsonify(ok=False, error="Current password is incorrect"), 400
    if len(new) < 8:
        return jsonify(ok=False, error="New password must be at least 8 characters"), 400
    if new != confirm:
        return jsonify(ok=False, error="New passwords do not match"), 400
    current_user.set_password(new)
    # Invalidate this account's other live sessions + remember-me cookies, then
    # re-issue the current session so the user who just changed it stays in.
    current_user.session_epoch = (current_user.session_epoch or 0) + 1
    db.session.commit()
    login_user(current_user)
    return jsonify(ok=True, message="Password changed")


@bp.route("/users", methods=["POST"])
@login_required
@admin_required
def user_create():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = request.form.get("role") or "user"
    if role not in ("admin", "user"):
        role = "user"
    if not username:
        return jsonify(ok=False, error="Username is required"), 400
    if len(password) < 8:
        return jsonify(ok=False, error="Password must be at least 8 characters"), 400
    if AdminUser.query.filter(db.func.lower(AdminUser.username) == username.lower()).first():
        return jsonify(ok=False, error=f"A user named “{username}” already exists"), 400
    u = AdminUser(username=username, role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    return jsonify(ok=True, message=f"User “{username}” added",
                   user={"id": u.id, "username": u.username, "role": u.role})


@bp.route("/users/<int:uid>/delete", methods=["POST"])
@login_required
@admin_required
def user_delete(uid):
    u = AdminUser.query.get_or_404(uid)
    if u.id == current_user.id:
        return jsonify(ok=False, error="You can't delete your own account"), 400
    if u.is_admin() and AdminUser.query.filter_by(role="admin").count() <= 1:
        return jsonify(ok=False, error="Can't delete the last admin"), 400
    db.session.delete(u)
    db.session.commit()
    return jsonify(ok=True, message=f"User “{u.username}” deleted", id=uid)
