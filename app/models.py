# SPDX-License-Identifier: AGPL-3.0-or-later
"""Data model for TS Pro Backup.

Four tables:

  * ``AdminUser``  — operators who sign into the web console.
  * ``Setting``    — a singleton row of server-wide config (Turnstile,
                     at-rest encryption, default retention policy).
  * ``Site``       — one connected TS Pro instance. Authenticates to the
                     API with a bearer key (stored only as a SHA-256
                     hash). Carries its own retention overrides.
  * ``Backup``     — one stored archive uploaded by a Site. Knows its
                     scope (``full`` whole-site vs ``frontend`` only),
                     original size / checksum, and whether the bytes on
                     disk are wrapped in the at-rest cipher.
"""
import hashlib
import secrets
from datetime import datetime, timedelta

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()

# Backup scopes. ``full`` is a whole-site export (DB + uploads + keys);
# ``frontend`` is the public web frontend only. Kept as plain strings so
# TS Pro can declare new scopes without a schema change here.
SCOPE_FULL = "full"
SCOPE_FRONTEND = "frontend"
SCOPES = (SCOPE_FULL, SCOPE_FRONTEND)
SCOPE_LABELS = {SCOPE_FULL: "Whole site", SCOPE_FRONTEND: "Frontend only"}

API_KEY_PREFIX = "tspb_"


class AdminUser(UserMixin, db.Model):
    __tablename__ = "admin_user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # 'admin' — full access incl. server settings + user management.
    # 'user'  — normal: manage sites/backups + own password, nothing else.
    role = db.Column(db.String(16), nullable=False, default="admin")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    # Set when the account still uses the shipped default password; the console
    # forces a change before anything else is reachable (see auth.force_password_change).
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    # Bumped on every password change. Baked into the Flask-Login session id
    # (get_id) and checked in the user loader, so changing the password
    # invalidates all other live sessions and remember-me cookies.
    session_epoch = db.Column(db.Integer, nullable=False, default=0)

    def set_password(self, raw):
        # Pin the KDF explicitly so the work factor doesn't silently change
        # with the installed Werkzeug version. scrypt is memory-hard.
        self.password_hash = generate_password_hash(raw, method="scrypt")

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    def get_id(self):
        # Flask-Login stores this in the session + remember cookie; the epoch
        # suffix lets _load_user reject tokens issued before a password change.
        return f"{self.id}-{self.session_epoch or 0}"

    def is_admin(self):
        return self.role == "admin"

    @property
    def role_label(self):
        return "Admin" if self.is_admin() else "User"


class LoginAttempt(db.Model):
    """One *failed* console sign-in, used for rate-limiting / lockout.

    The console has no external rate-limiter (no Redis), so we persist
    failures in the DB: state then survives across the multiple gunicorn
    workers and across restarts. One row per failed attempt, keyed by both
    the (lower-cased) submitted username and the client IP so we can lock
    on either axis. Rows older than the lockout window never count and are
    pruned opportunistically (see ``app/loginguard.py``)."""
    __tablename__ = "login_attempt"
    id = db.Column(db.Integer, primary_key=True)
    # The username string that was *submitted* (not necessarily a real
    # account) — locking on the raw input means an attacker pounding a
    # bogus name locks only that name, leaking nothing about who exists.
    username = db.Column(db.String(80), index=True)
    ip = db.Column(db.String(45), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class Setting(db.Model):
    """Server-wide singleton (always row id=1)."""
    __tablename__ = "setting"
    id = db.Column(db.Integer, primary_key=True)

    # Cloudflare Turnstile (gates the console login form).
    turnstile_enabled = db.Column(db.Boolean, nullable=False, default=False)
    turnstile_site_key = db.Column(db.String(255))
    turnstile_secret_key_enc = db.Column(db.LargeBinary)

    # End-to-end encryption enforcement. When on, the API rejects any
    # upload that isn't already encrypted by the client (TS Pro) before
    # it left — guaranteeing the server only ever stores ciphertext it
    # has no key for (zero-knowledge). On by default: secure by default.
    require_e2ee = db.Column(db.Boolean, nullable=False, default=True)

    # Server-side encryption at rest with AES-256-GCM (see app/restenc).
    # NOTE: this uses a key the SERVER holds, so it protects a stolen
    # disk but is NOT end-to-end. Independent of require_e2ee. Off by
    # default — with E2EE on, the bytes are already opaque to us.
    encrypt_at_rest = db.Column(db.Boolean, nullable=False, default=False)

    # Default Grandfather-Father-Son retention, applied per (site, scope)
    # unless the site overrides it. "Keep the most recent N distinct
    # days / weeks / months / years." 0 disables that tier.
    keep_daily = db.Column(db.Integer, nullable=False, default=7)
    keep_weekly = db.Column(db.Integer, nullable=False, default=4)
    keep_monthly = db.Column(db.Integer, nullable=False, default=12)
    keep_yearly = db.Column(db.Integer, nullable=False, default=3)

    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @classmethod
    def get(cls):
        row = cls.query.get(1)
        if row is None:
            row = cls(id=1)
            db.session.add(row)
            try:
                db.session.commit()
            except IntegrityError:
                # Concurrent first-boot worker already created the singleton.
                db.session.rollback()
                row = cls.query.get(1)
        return row


class OneTimeSecret(db.Model):
    """Server-side stash backing the show-once credential reveal modal.

    Flask sessions are client-side cookies — signed but NOT encrypted — so a
    freshly minted API key or E2EE private key must never ride in one (any
    cookie copy could be base64-decoded to the secret). Instead the secrets
    are Fernet-encrypted into this table and the session carries only a
    random nonce. The row is deleted on first read, and a TTL sweep clears
    anything never picked up, so each secret transits exactly one response.
    A table (not an in-process cache) so the reveal survives the multi-worker
    gunicorn split."""
    __tablename__ = "one_time_secret"
    id = db.Column(db.Integer, primary_key=True)
    nonce = db.Column(db.String(64), unique=True, nullable=False, index=True)
    site_id = db.Column(db.Integer, index=True)
    api_key_enc = db.Column(db.LargeBinary)
    privkey_enc = db.Column(db.LargeBinary)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    TTL_MINUTES = 15

    @classmethod
    def stash(cls, site_id, api_key=None, privkey=None) -> str:
        """Store the secrets, return the nonce to put in the session."""
        from .crypto import encrypt
        cls._sweep()
        nonce = secrets.token_urlsafe(32)
        db.session.add(cls(
            nonce=nonce, site_id=site_id,
            api_key_enc=encrypt(api_key) if api_key else None,
            privkey_enc=encrypt(privkey) if privkey else None))
        db.session.commit()
        return nonce

    @classmethod
    def pop(cls, nonce):
        """One-shot read: return (site_id, api_key, privkey) and delete the
        row, or None if the nonce is unknown/expired/already read."""
        from .crypto import decrypt
        cls._sweep()
        if not nonce:
            return None
        row = cls.query.filter_by(nonce=nonce).first()
        if row is None:
            return None
        out = (row.site_id,
               decrypt(row.api_key_enc) if row.api_key_enc else None,
               decrypt(row.privkey_enc) if row.privkey_enc else None)
        db.session.delete(row)
        db.session.commit()
        return out

    @classmethod
    def _sweep(cls):
        cutoff = datetime.utcnow() - timedelta(minutes=cls.TTL_MINUTES)
        cls.query.filter(cls.created_at < cutoff).delete()


class Site(db.Model):
    """A connected TS Pro instance."""
    __tablename__ = "site"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    # API key: we keep only the SHA-256 hash for verification plus a
    # short visible prefix so the operator can recognise it in the UI.
    # The full key is shown exactly once, at creation / rotation.
    api_key_hash = db.Column(db.String(64), unique=True, index=True)
    api_key_prefix = db.Column(db.String(16))

    # End-to-end encryption recipient. We store ONLY the site's public
    # key (a ``tsppk_…`` string, not a secret) — the client encrypts each
    # backup to it. The matching private key is shown to the operator
    # exactly once at creation / rotation and is never persisted here, so
    # the server can never decrypt what it stores. See ``app/pubkey.py``.
    e2ee_public_key = db.Column(db.String(80))
    # False from the moment a keypair is issued until the operator confirms
    # they've stored the (shown-once) private key. Drives a persistent
    # reminder banner — we can't know whether they actually saved it, so we
    # keep nagging until they say so. Reset to False on every rotation.
    e2ee_key_ack = db.Column(db.Boolean, nullable=False, default=False)

    # Per-site retention overrides. NULL on a tier means "inherit the
    # server default for that tier".
    keep_daily = db.Column(db.Integer)
    keep_weekly = db.Column(db.Integer)
    keep_monthly = db.Column(db.Integer)
    keep_yearly = db.Column(db.Integer)

    # Per-site overrides: NULL inherits the server default; True/False
    # force on/off for this site.
    require_e2ee = db.Column(db.Boolean)
    encrypt_at_rest = db.Column(db.Boolean)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime)
    last_seen_ip = db.Column(db.String(45))

    # ── Remote restore (push a stored backup back into the live site) ──
    # Populated by the site itself over POST /api/v1/register: its public
    # base URL (where its inbound /api/v1/restore endpoints live) and a
    # shared restore token we present to authenticate the push. The token
    # is a high-value secret — store it Fernet-encrypted, never in clear.
    # ``restore_enabled`` mirrors the site's own opt-in: the operator must
    # turn remote restore on at the TS Pro end before we ever offer it.
    restore_callback_url = db.Column(db.String(500))
    restore_token_enc = db.Column(db.LargeBinary)
    restore_enabled = db.Column(db.Boolean, nullable=False, default=False)
    restore_registered_at = db.Column(db.DateTime)
    restore_registered_ip = db.Column(db.String(45))
    # The (url, token-hash) pair the operator last confirmed on the restore
    # page. Anyone holding the site's API key can re-point the callback URL
    # via /register, so the restore page compares the live pair against this
    # and demands an explicit re-confirmation (typing the hostname) whenever
    # they differ — a silently moved endpoint can't phish the private key.
    restore_url_acked = db.Column(db.String(600))
    # Admin-pinned expected callback host. When set, /register refuses to
    # move the callback URL to any other host — a leaked API key alone can
    # no longer steer restores off-site.
    restore_url_pinned = db.Column(db.String(255))

    backups = db.relationship(
        "Backup", backref="site", cascade="all, delete-orphan",
        order_by="Backup.created_at.desc()",
    )

    # ── API key helpers ────────────────────────────────────────────
    @staticmethod
    def _hash_key(raw: str) -> str:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def issue_api_key(self) -> str:
        """Generate a fresh key, store its hash + prefix, return the
        plaintext (caller must show it once and never persist it)."""
        raw = API_KEY_PREFIX + secrets.token_urlsafe(32)
        self.api_key_hash = self._hash_key(raw)
        self.api_key_prefix = raw[:12]
        return raw

    @classmethod
    def authenticate(cls, raw_key: str):
        if not raw_key:
            return None
        return cls.query.filter_by(
            api_key_hash=cls._hash_key(raw_key.strip()), enabled=True
        ).first()

    # ── E2EE keypair helpers ────────────────────────────────────────
    def issue_keypair(self) -> str:
        """Generate a fresh X25519 keypair, store the public half on the
        row, return the private key (a ``tspsk_…`` string) for the caller
        to show once and never persist. Rotating invalidates every backup
        previously encrypted to the old public key — they can still be
        decrypted with the *old* private key the operator kept."""
        from . import pubkey
        public, private = pubkey.generate_keypair()
        self.e2ee_public_key = public
        self.e2ee_key_ack = False  # operator hasn't confirmed saving this one yet
        return private

    @property
    def e2ee_fingerprint(self):
        from . import pubkey
        if not self.e2ee_public_key:
            return None
        return pubkey.fingerprint(self.e2ee_public_key)

    # ── Remote-restore pairing helpers ─────────────────────────────
    def set_restore_token(self, raw: str):
        """Store (Fernet-encrypted) the shared token the site published, or
        clear it when the site disables remote restore."""
        from .crypto import encrypt
        self.restore_token_enc = encrypt(raw) if raw else None

    @property
    def restore_token(self) -> str:
        """The plaintext restore token to present when pushing a restore."""
        from .crypto import decrypt
        return decrypt(self.restore_token_enc) if self.restore_token_enc else ""

    @property
    def restore_ready(self) -> bool:
        """True when this site can actually receive a remote restore: it
        opted in and published both a callback URL and a token."""
        return bool(self.restore_enabled and self.restore_callback_url
                    and self.restore_token_enc)

    def _restore_endpoint_pair(self):
        """Canonical '<sha256(token)>|<url>' string identifying the current
        restore endpoint. Token is hashed so the ack column never stores it."""
        if not (self.restore_callback_url and self.restore_token_enc):
            return None
        token_hash = hashlib.sha256(self.restore_token.encode("utf-8")).hexdigest()
        return f"{token_hash}|{self.restore_callback_url}"

    @property
    def restore_endpoint_changed(self) -> bool:
        """True when the live callback URL/token differs from what the
        operator last confirmed (or was never confirmed at all)."""
        current = self._restore_endpoint_pair()
        return bool(current) and current != self.restore_url_acked

    def ack_restore_endpoint(self):
        """Record that the operator verified the current endpoint."""
        self.restore_url_acked = self._restore_endpoint_pair()

    @property
    def restore_host(self):
        """Hostname of the registered callback URL (what the operator must
        re-type to confirm a changed endpoint)."""
        from urllib.parse import urlsplit
        if not self.restore_callback_url:
            return None
        return (urlsplit(self.restore_callback_url).hostname or "").lower() or None

    # ── effective retention (override → default) ───────────────────
    def retention(self, settings):
        def pick(site_val, default_val):
            return default_val if site_val is None else site_val
        return {
            "daily": pick(self.keep_daily, settings.keep_daily),
            "weekly": pick(self.keep_weekly, settings.keep_weekly),
            "monthly": pick(self.keep_monthly, settings.keep_monthly),
            "yearly": pick(self.keep_yearly, settings.keep_yearly),
        }

    def effective_encrypt_at_rest(self, settings):
        if self.encrypt_at_rest is None:
            return bool(settings.encrypt_at_rest)
        return bool(self.encrypt_at_rest)

    def effective_require_e2ee(self, settings):
        if self.require_e2ee is None:
            return bool(settings.require_e2ee)
        return bool(self.require_e2ee)

    @property
    def total_bytes(self):
        return sum(b.size_bytes or 0 for b in self.backups)


class Backup(db.Model):
    """One stored archive."""
    __tablename__ = "backup"
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id", ondelete="CASCADE"),
                        nullable=False, index=True)

    # ``full`` | ``frontend`` (see SCOPES). Retention runs independently
    # per scope so frontend snapshots never evict whole-site ones.
    scope = db.Column(db.String(32), nullable=False, default=SCOPE_FULL, index=True)

    original_name = db.Column(db.String(255), nullable=False)
    # Opaque on-disk filename (uuid) under the site's storage dir.
    stored_name = db.Column(db.String(255), nullable=False)

    # ``size_bytes`` is the size of the archive TS Pro sent (the logical
    # backup size, before any at-rest wrapping). ``stored_bytes`` is what
    # actually sits on disk (larger if we encrypted it at rest).
    size_bytes = db.Column(db.BigInteger, nullable=False, default=0)
    stored_bytes = db.Column(db.BigInteger, nullable=False, default=0)
    sha256 = db.Column(db.String(64))  # checksum of the original bytes

    # True if WE wrapped it in the at-rest cipher (must be unwrapped on
    # download). Independent of ``client_encrypted``.
    encrypted_at_rest = db.Column(db.Boolean, nullable=False, default=False)
    # True if the incoming archive is a well-formed client-side envelope
    # (TSPEPK01 public-key, or TSPENC01 passphrase). This is a STRUCTURAL
    # signal, not cryptographic proof — the UI labels it accordingly.
    client_encrypted = db.Column(db.Boolean, nullable=False, default=False)

    # Fingerprint of the site public key the backup was encrypted to (when it
    # is a TSPEPK01 envelope), captured at ingest. Lets an operator who has
    # rotated keypairs tell which saved private key restores this archive.
    e2ee_fingerprint = db.Column(db.String(40))

    note = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    @property
    def scope_label(self):
        return SCOPE_LABELS.get(self.scope, self.scope)
