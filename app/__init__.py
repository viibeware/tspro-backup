# SPDX-License-Identifier: AGPL-3.0-or-later
"""TS Pro Backup — application factory.

A standalone Flask service that receives off-site backups from one or
more Trusted Servants Pro instances over an authenticated HTTP API,
stores them (optionally AES-256 encrypted at rest), enforces a
grandfather-father-son retention policy, and offers a web console — built
to match the TS Pro look — for operators to manage sites and browse
backups.

Like TS Pro itself there is no Alembic: ``_migrate_sqlite`` additively
patches columns onto existing tables at boot, ``db.create_all`` handles
fresh installs.
"""
import os
import sqlite3
from datetime import datetime, timedelta

from flask import Flask
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix

from .crypto import init_fernet
from .models import AdminUser, Setting, db
from .version import __version__

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = None
csrf = CSRFProtect()


@event.listens_for(Engine, "connect")
def _sqlite_fk_pragma(dbapi_connection, connection_record):
    # SQLite defaults foreign_keys=OFF per connection, which makes our
    # ondelete=CASCADE inert — a Site delete would leave orphaned Backup rows
    # (and their on-disk blobs) behind. Enforce it on every sqlite connection.
    if isinstance(dbapi_connection, sqlite3.Connection):
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


def create_app():
    app = Flask(__name__)

    data_dir = os.environ.get("TSPB_DATA_DIR", "/data")
    os.makedirs(data_dir, exist_ok=True)
    db_path = os.path.join(data_dir, "tspro_backup.db")

    max_mb = int(os.environ.get("TSPB_MAX_UPLOAD_MB", "8192"))
    # Plain-HTTP dev disables the Secure cookie flag. Used for both the
    # session and the (equally sensitive) Flask-Login remember cookie.
    secure_cookies = os.environ.get("TSPB_DEBUG", "").lower() not in ("1", "true", "yes")

    app.config.update(
        SECRET_KEY=_resolve_secret_key(data_dir),
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{db_path}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        DATA_DIR=data_dir,
        DB_PATH=db_path,
        VERSION=__version__,
        MAX_CONTENT_LENGTH=max_mb * 1024 * 1024,
        # Failed-console-login lockout (see app/loginguard.py): after
        # LOGIN_MAX_FAILURES failures for a username or IP within
        # LOGIN_WINDOW_MINUTES, further sign-ins are refused until the
        # oldest failures age out. 0 failures disables the lockout.
        LOGIN_MAX_FAILURES=int(os.environ.get("TSPB_LOGIN_MAX_FAILURES", "5")),
        LOGIN_WINDOW_MINUTES=int(os.environ.get("TSPB_LOGIN_WINDOW_MINUTES", "15")),
        # Secure cookie unless explicitly running over plain HTTP for dev.
        SESSION_COOKIE_SECURE=secure_cookies,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # The persistent "remember me" cookie is an auth credential too —
        # give it the same protections as the session cookie (Flask-Login
        # otherwise defaults it to Secure=False, SameSite=None).
        REMEMBER_COOKIE_SECURE=secure_cookies,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Lax",
        # Flask-Login's default remember-me lifetime is 365 days — far too
        # long for a bearer credential on a backup vault's console.
        REMEMBER_COOKIE_DURATION=timedelta(
            days=int(os.environ.get("TSPB_REMEMBER_DAYS", "14"))),
    )

    # Behind Caddy / Cloudflare: trust one proxy hop for scheme + client IP
    # so Turnstile sees the real remote address and url_for builds https.
    # SECURITY: ProxyFix makes request.remote_addr follow the client-supplied
    # X-Forwarded-For header, which the login lockout keys on. That is only
    # safe when a TRUSTED proxy (that overwrites XFF) is the sole ingress. If
    # the listening port is reachable directly, an attacker spoofs XFF to
    # defeat the per-IP lockout — so gate it behind an explicit opt-in.
    # Default on preserves the documented behind-a-proxy deployment.
    if os.environ.get("TSPB_TRUST_PROXY", "1").lower() in ("1", "true", "yes"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db.init_app(app)
    init_fernet(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from .auth import bp as auth_bp
    from .routes import bp as main_bp
    from .api import bp as api_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)
    # TS Pro instances authenticate with an API key, not a session cookie —
    # the API is stateless, so exempt it from form-CSRF entirely.
    csrf.exempt(api_bp)

    _register_jinja(app)
    _register_security_headers(app, secure_cookies)
    _register_password_gate(app)

    with app.app_context():
        db.create_all()
        _migrate_sqlite(db)
        Setting.get()  # ensure singleton exists
        _seed_admin(app)
        _flag_default_passwords(app)

    # The DB holds API-key hashes, settings and the encrypted Turnstile secret;
    # don't leave it world-readable next to the other 0600 secrets in DATA_DIR.
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        pass

    # Reap abandoned chunk-upload staging dirs on a timer, independent of traffic.
    from .api import start_chunk_reaper
    start_chunk_reaper(app)

    return app


@login_manager.user_loader
def _load_user(user_id):
    # IDs are "<pk>-<session_epoch>" (see AdminUser.get_id). A token whose epoch
    # no longer matches the row was issued before a password change → reject it.
    uid, _, epoch = str(user_id).partition("-")
    try:
        user = AdminUser.query.get(int(uid))
    except (TypeError, ValueError):
        return None
    if user is None or epoch != str(user.session_epoch or 0):
        return None
    return user


def _resolve_secret_key(data_dir):
    """The Flask session/CSRF signing key.

    Prefer ``TSPB_SECRET_KEY``. If it is unset we must NOT fall back to a
    shipped constant — a known signing key lets anyone forge an admin
    session cookie and walk straight past the login form (and its lockout).
    Instead generate a random key once and persist it under the data dir,
    mirroring the existing rest.key / secret.key pattern, so it survives
    restarts while never being a value an attacker could know."""
    key = os.environ.get("TSPB_SECRET_KEY")
    if key:
        return key
    path = os.path.join(data_dir, "session.key")
    if os.path.exists(path):
        with open(path) as f:
            stored = f.read().strip()
        if stored:
            return stored
    import secrets
    key = secrets.token_urlsafe(48)
    with open(path, "w") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


# Content-Security-Policy for the console. 'unsafe-inline' is required because
# the templates use inline <script> blocks, inline on*= handlers and inline
# style= attributes; the Cloudflare origin is whitelisted for the (optional)
# Turnstile widget's script + iframe. Even with 'unsafe-inline' this still
# blocks third-party script origins, framing (clickjacking), off-site form
# posts and base-tag hijacking. Tightening to nonces is a future refactor.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-src https://challenges.cloudflare.com; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def _register_security_headers(app, secure):
    """Conservative response hardening for the console."""
    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        # MUST keep the same-origin Referer: Flask-WTF's CSRF protection does a
        # strict referrer check over HTTPS (WTF_CSRF_SSL_STRICT) and rejects a
        # POST whose Referer is missing. 'no-referrer' would strip it and break
        # every console form. 'same-origin' still withholds it from other sites.
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Content-Security-Policy", _CSP)
        # Neutralize the version-leaking dev-server banner (Werkzeug would
        # otherwise send "Werkzeug/x Python/y"). In production gunicorn sets
        # its own versionless "Server: gunicorn" at the WSGI layer and wins;
        # stripping that entirely is a reverse-proxy concern.
        resp.headers["Server"] = "tspro-backup"
        if secure:  # only assert HSTS when we're actually serving over TLS
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp


def _seed_admin(app):
    if AdminUser.query.first() is not None:
        return
    username = os.environ.get("TSPB_ADMIN_USERNAME", "admin")
    password = os.environ.get("TSPB_ADMIN_PASSWORD", "admin")
    u = AdminUser(username=username, role="admin")
    u.set_password(password)
    db.session.add(u)
    try:
        db.session.commit()
        app.logger.info("Seeded initial admin user %r", username)
    except IntegrityError:
        # Two gunicorn workers can boot against a fresh DB at once and both try
        # to seed — the loser hits a UNIQUE violation. Benign: the admin exists.
        db.session.rollback()


def _flag_default_passwords(app):
    """Force a password change for any account still using the shipped default
    password ('admin'). Covers both a freshly seeded admin/admin and an
    existing deployment that was never rotated."""
    try:
        changed = False
        for u in AdminUser.query.all():
            if not u.must_change_password and u.check_password("admin"):
                u.must_change_password = True
                changed = True
                app.logger.warning(
                    "account %r still uses the default password — forcing a "
                    "change on next sign-in", u.username)
        if changed:
            db.session.commit()
    except Exception:  # noqa: BLE001 — never block boot on this hygiene check
        db.session.rollback()


def _register_password_gate(app):
    """While a signed-in operator must_change_password, funnel every request to
    the change-password wizard (except the wizard itself, logout, and static)."""
    from flask import redirect, request, url_for
    from flask_login import current_user

    _allowed = {"auth.force_password_change", "auth.logout", "static"}

    @app.before_request
    def _force_password_change():
        if not current_user.is_authenticated:
            return None
        if not getattr(current_user, "must_change_password", False):
            return None
        if request.endpoint in _allowed:
            return None
        return redirect(url_for("auth.force_password_change"))


def _migrate_sqlite(db):
    """Additively patch columns missing from existing tables. Mirrors TS
    Pro's approach: every column added to a model after first release must
    get an entry here so upgraded deployments don't break."""
    from sqlalchemy import text

    def cols(table):
        rows = db.session.execute(text(f"PRAGMA table_info({table})")).fetchall()
        return {r[1] for r in rows}

    def add(table, name, ddl):
        # Commit each column on its own and swallow a concurrent "duplicate
        # column" — with multiple gunicorn workers booting at once, two can
        # race the same ALTER; the loser's error is benign.
        if name in cols(table):
            return
        try:
            db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {ddl}"))
            db.session.commit()
        except Exception:  # noqa: BLE001
            db.session.rollback()

    try:
        existing = {r[0] for r in db.session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        if "setting" in existing:
            add("setting", "require_e2ee", "require_e2ee BOOLEAN DEFAULT 1")
            add("setting", "encrypt_at_rest", "encrypt_at_rest BOOLEAN DEFAULT 0")
            add("setting", "keep_daily", "keep_daily INTEGER DEFAULT 7")
            add("setting", "keep_weekly", "keep_weekly INTEGER DEFAULT 4")
            add("setting", "keep_monthly", "keep_monthly INTEGER DEFAULT 12")
            add("setting", "keep_yearly", "keep_yearly INTEGER DEFAULT 3")
        if "admin_user" in existing:
            add("admin_user", "role", "role VARCHAR(16) DEFAULT 'admin'")
            add("admin_user", "must_change_password", "must_change_password BOOLEAN DEFAULT 0")
            add("admin_user", "session_epoch", "session_epoch INTEGER DEFAULT 0")
        if "site" in existing:
            add("site", "require_e2ee", "require_e2ee BOOLEAN")
            add("site", "encrypt_at_rest", "encrypt_at_rest BOOLEAN")
            add("site", "last_seen_ip", "last_seen_ip VARCHAR(45)")
            add("site", "e2ee_public_key", "e2ee_public_key VARCHAR(80)")
            add("site", "e2ee_key_ack", "e2ee_key_ack BOOLEAN DEFAULT 0")
            add("site", "restore_callback_url", "restore_callback_url VARCHAR(500)")
            add("site", "restore_token_enc", "restore_token_enc BLOB")
            add("site", "restore_enabled", "restore_enabled BOOLEAN DEFAULT 0")
            add("site", "restore_registered_at", "restore_registered_at DATETIME")
            add("site", "restore_registered_ip", "restore_registered_ip VARCHAR(45)")
            add("site", "restore_url_acked", "restore_url_acked VARCHAR(600)")
            add("site", "restore_url_pinned", "restore_url_pinned VARCHAR(255)")
        if "backup" in existing:
            add("backup", "client_encrypted", "client_encrypted BOOLEAN DEFAULT 0")
            add("backup", "note", "note VARCHAR(500)")
            add("backup", "e2ee_fingerprint", "e2ee_fingerprint VARCHAR(40)")
        db.session.commit()
    except Exception as e:  # noqa: BLE001 — never let a migration crash boot
        db.session.rollback()
        import logging
        logging.getLogger(__name__).warning("migration skipped: %s", e)


def _register_jinja(app):
    from flask_login import current_user
    from .icons import ICONS

    @app.context_processor
    def inject_globals():
        # The settings modal lives in base.html on every authenticated page;
        # only an admin needs the user list, so skip the query otherwise.
        console_users = []
        if current_user.is_authenticated and current_user.is_admin():
            console_users = AdminUser.query.order_by(AdminUser.username).all()
        return {
            "app_version": __version__,
            "settings": Setting.get(),
            "console_users": console_users,
            "now": datetime.utcnow(),
            "icon": lambda name: ICONS.get(name, ""),
        }

    @app.template_filter("fmt_bytes")
    def fmt_bytes(n):
        n = float(n or 0)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024 or unit == "TB":
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024

    @app.template_filter("fmt_dt")
    def fmt_dt(dt):
        if not dt:
            return "—"
        return dt.strftime("%Y-%m-%d %H:%M UTC")

    @app.template_filter("ago")
    def ago(dt):
        if not dt:
            return "never"
        delta = datetime.utcnow() - dt
        s = int(delta.total_seconds())
        if s < 60:
            return "just now"
        if s < 3600:
            return f"{s // 60}m ago"
        if s < 86400:
            return f"{s // 3600}h ago"
        return f"{s // 86400}d ago"
