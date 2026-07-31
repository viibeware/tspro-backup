# Changelog

All notable changes to **TS Pro Backup** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.2] — 2026-07-31

Security-hardening patch release focused on the remote-restore path.
**Upgrades are safe and automatic** (additive schema migration on boot).

### Security

- **Restore pushes no longer follow HTTP redirects.** A site (or a proxy in
  front of it) answering the restore push with a 30x used to be followed —
  re-sending the restore token and the operator's private key to the redirect
  target, potentially over plain HTTP. Any redirect is now a hard error, the
  https requirement is enforced per request, and connect/read timeouts are
  honored so a hung site can't pin worker threads.
- **Changed restore endpoints require re-confirmation.** Anyone holding a
  site's API key can re-register its restore callback URL. The restore page
  now tracks the endpoint the operator last confirmed; if it changed (or was
  never confirmed) a warning banner appears and the operator must type the
  endpoint's full hostname — not just RESTORE — before a push is accepted.
  Admins can additionally **pin** the expected callback host per site, every
  (re)registration is logged with old→new URL and origin IP, and
  registration URLs containing credentials are rejected.
- **Show-once secrets no longer transit the session cookie.** Newly issued
  API keys and E2EE private keys were stashed in the (signed but unencrypted)
  client-side session cookie for the reveal modal. They now live in a
  server-side one-time store — Fernet-encrypted, deleted on first read,
  15-minute TTL — and the cookie carries only a random nonce.
- **Dependency updates.** Flask 3.1.3, Werkzeug 3.1.6, cryptography 48.0.1,
  requests 2.33.0 — clearing all known advisories reported by `pip-audit`.
- **Upload capacity checks are race-free and count peak usage.** Chunk
  uploads are checked against free-disk headroom *before* bytes land on disk
  and are serialized per upload; finalize accounts for staging + reassembled
  + stored copies existing at once; stored blobs are written via a `.part`
  name and renamed only when complete, with partials removed on failure.
- **Hygiene.** Failed API authentications are logged (IP + 8-char key prefix,
  rate-limited); deleting a site also removes its staged chunk uploads; the
  background reaper now sweeps orphaned transfer temp files from the data
  volume; outbound restore filenames are stripped of control characters; the
  console “remember me” cookie now lasts 14 days (was 365, tunable via
  `TSPB_REMEMBER_DAYS`); the compose file drops all container capabilities
  except the four the entrypoint needs and caps container memory.

### Added

- A `tests/` pytest suite covering the regressions above (redirect refusal,
  endpoint re-confirmation, reveal-once semantics, capacity/cleanup/reaper
  behaviour, auth-failure logging).

## [1.3.1] — 2026-07-04

Maintenance release. Moves the project's GitHub repository and Docker Hub
image to the **hyprlab** account. No code or behaviour changes — upgrades
are safe and automatic.

### Changed

- **New home.** Source now lives at
  [`hyprlab/tspro-backup`](https://github.com/hyprlab/tspro-backup) and the
  published image at
  [`hyprlab/tspro-backup`](https://hub.docker.com/r/hyprlab/tspro-backup).
  Update your `docker-compose.yml` `image:` reference accordingly.

## [1.3.0] — 2026-06-07

Adds **remote restore** — an out-of-band recovery path that pushes a stored
backup from this console back into the live TS Pro site it came from, for
when that site's data is corrupted or its admin is locked out. **Upgrades are
safe and automatic; the feature is off until a site opts in.** Requires TS Pro
**2.11.0+** on the connected site.

### Added

- **Remote restore (push a backup back to the live site).** From a site's
  full backups in the console you can now push a stored archive back into the
  running TS Pro install, which decrypts and applies it without needing any
  admin login on the site — recovering a corrupted database, a locked-out
  admin, or an accidental login/IP lockout. The site applies it through its
  existing import path (snapshots the old data first, clears login lockouts,
  recycles workers).
- **Auto-pairing over the existing API.** A site publishes its public URL and
  a shared restore token to this server via the new `POST /api/v1/register`
  endpoint (called from the TS Pro backup target on save / "Test connection"),
  mirroring how `/ping` already hands out the E2EE public key. `/ping` now
  advertises a `remote_restore` capability. The site page shows pairing status.
- **Restore push client** (`app/restore_push.py`): streams the stored
  ciphertext (single-shot or chunked, to clear a proxy body cap) to the site's
  inbound restore endpoints, refusing plain HTTP unless `TSPB_DEBUG` is set.

### Security

- **Two independent secrets gate every restore.** The push carries the shared
  restore token (authenticates it) **and** the operator's private key, which
  the site requires to both decrypt the archive and confirm it matches the
  public key on file — so a stolen token alone cannot push a malicious
  archive. The token is Fernet-encrypted at rest, compared in constant time,
  and the whole feature is **off by default** (the site must opt in).
- **The server stays zero-knowledge.** It only ever forwards ciphertext; the
  private key the operator pastes at restore time transits this server
  in-memory and is never written to disk or logs.

### Schema

- `Site` gains `restore_callback_url`, `restore_token_enc`, `restore_enabled`,
  and `restore_registered_at` (additive boot migration).

## [1.2.1] — 2026-06-02

### Fixed

- **Console login broke with `400 Bad Request: The referrer header is missing.`
  over HTTPS.** The `Referrer-Policy: no-referrer` header introduced in 1.1.0
  made browsers omit the `Referer` header, which Flask-WTF's strict CSRF
  referrer check (`WTF_CSRF_SSL_STRICT`, on over HTTPS) requires — so every
  console form POST, including sign-in, was rejected on a TLS deployment.
  Changed the policy to `same-origin`, which keeps the `Referer` on
  same-origin requests (still withholding it from external sites). **Anyone
  running 1.1.0 or 1.2.0 behind TLS should upgrade to 1.2.1.**

## [1.2.0] — 2026-06-02

A follow-up hardening release that completes the privilege-separation work
and adds defence-in-depth from the security review. **Upgrades are safe and
automatic.**

### Security

- **Limited `user` role enforced.** Non-admin (`user`) operators can no longer
  rotate a site's API key or encryption keypair, delete a site, or change a
  site's encryption policy (`require_e2ee` / `encrypt_at_rest`) — those are now
  admin-only, enforced server-side and hidden in the UI. `user` accounts keep
  "manage sites & backups" (create/edit a site's name + retention, browse and
  delete backups).
- **Content-Security-Policy** added to console responses (alongside the
  existing `X-Frame-Options` / `X-Content-Type-Options` / `Referrer-Policy` /
  HSTS): restricts scripts to same-origin + Cloudflare Turnstile, forbids
  framing, off-site form posts, and base-tag hijacking.
- **Transient files kept on the data volume.** Upload staging and at-rest
  decrypt temp files now live under `<DATA_DIR>/tmp` (mode `0700`) instead of
  the shared system `/tmp`, so any transient plaintext stays on the controlled,
  owner-only volume and disk accounting is honest.
- The development-server `Server` banner no longer leaks the Werkzeug/Python
  version.

### Changed

- **Threaded workers.** gunicorn now uses the `gthread` worker class
  (`-w 2 --threads 4`), so a couple of slow multi-GB transfers can't tie up
  every worker and stall the console.

## [1.1.0] — 2026-06-02

A security-hardening release. Following a full multi-agent security review,
this adds brute-force protection to the console login and closes a range of
authentication, encryption-integrity, and denial-of-service gaps. **Upgrades
are safe and automatic**, with three one-time effects noted below.

### Security

- **Console login lockout.** Failed sign-ins are rate-limited with a
  DB-backed sliding window — after `TSPB_LOGIN_MAX_FAILURES` (default 5)
  failures for a username **or** client IP within `TSPB_LOGIN_WINDOW_MINUTES`
  (default 15), further attempts are refused (HTTP 429) until the oldest
  failures age out. Holds across workers and restarts.
- **No more usable default signing key.** `TSPB_SECRET_KEY`, when unset, now
  auto-generates and persists a random key to `data/session.key` instead of
  falling back to a shipped constant — closing an admin-session-forgery path
  for non-compose deployments.
- **Forced password change.** An account still using the default `admin`
  password is funnelled through a one-time change wizard on first sign-in
  (covers both fresh and existing deployments).
- **Username-enumeration timing fixed** (a dummy hash equalises the
  missing-user path) and the **lockout now runs after Turnstile**, so a
  challenge can't be skipped to spray a known username.
- **Password change invalidates other sessions** and remember-me cookies
  (a per-account session epoch baked into the login token).
- **End-to-end encryption gate hardened.** The upload gate now validates the
  full `TSPEPK01` envelope **structure** (magic + 32-byte X25519 key + nonce
  + tag) instead of an 8-byte magic prefix, and **rejects** uploads to an
  E2EE-required site that has no encryption key. The per-backup recipient-key
  fingerprint is recorded and shown. (The guarantee is now labelled honestly:
  the server holds no private key, so it validates format, not ciphertext.)
- **Upload denial-of-service caps.** Chunked uploads now enforce a per-chunk
  cap, a `total_chunks` cap, a cumulative-size cap, and a free-disk check,
  plus an optional per-site storage quota (`TSPB_SITE_QUOTA_MB`) — one site
  key can no longer fill the disk. `total_chunks` is mandatory at finalize and
  chunks must be contiguous, so a partial upload can't become a silently
  truncated backup.
- **Container runs as a non-root user**, with secure response headers
  (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, HSTS),
  hardened `remember-me` cookie flags, `0600` DB and blob permissions,
  POST-only `/logout`, and the Werkzeug interactive debugger split onto its
  own `TSPB_FLASK_DEBUG` flag (never via `TSPB_DEBUG`).
- Bumped **Werkzeug to 3.0.6** (CVE-2024-49767, multipart-parser DoS) and
  **requests to 2.32.4**.

### Added

- New env vars: `TSPB_TRUST_PROXY` (trust `X-Forwarded-*`; default `1`),
  `TSPB_LOGIN_MAX_FAILURES`, `TSPB_LOGIN_WINDOW_MINUTES`, `TSPB_SITE_QUOTA_MB`,
  `TSPB_FLASK_DEBUG`, `TSPB_CHUNK_TTL_HOURS`, `TSPB_DISK_MARGIN_MB`.
- `/api/v1/ping` now advertises `max_backup_mb`.

### Fixed

- **Fresh-boot crash race.** Two workers booting against an empty database
  could both seed the admin / settings singleton, crash-looping the service;
  seeding is now race-safe.
- `PRAGMA foreign_keys=ON` is enforced, so deleting a site cascades to its
  backup rows (and on-disk blobs) instead of orphaning them.

### Upgrade notes

- All current console sessions are invalidated once (the session token format
  changed) — operators simply sign in again.
- Any admin still using the `admin` password is sent through the forced
  change wizard on next sign-in.
- A site that has E2EE required but no encryption key must have its keypair
  rotated in the console before it can accept uploads again.

## [1.0.2] — 2026-06-02

### Changed

- **Adaptive credentials modal.** The one-time site-credentials reveal now
  has a fixed header and footer with an internally-scrolling body, so it
  fits any viewport height instead of overflowing on short screens — the
  title and the **Done** button stay visible while the key fields scroll.
- **Mobile-responsive credentials modal.** Tighter padding on small screens,
  full-width copy buttons that wrap instead of overflowing, and `100dvh`
  sizing that accounts for mobile browser chrome.

## [1.0.1] — 2026-06-02

### Added

- **API endpoint in the credentials modal.** The one-time site-credentials
  reveal now shows the API endpoint (`…/api/v1`) with its own copy button,
  alongside the API key and private key — no need to hunt for it separately.
- **Encryption key fingerprint in the credentials modal.** The site's
  public-key fingerprint is shown and copyable in the same modal, so you can
  confirm it against TS Pro right after creating or rotating a keypair.

### Changed

- **Click-to-copy connection details.** On the site edit page, the API
  endpoint and encryption key fingerprint are now click-to-copy, with a
  hover tooltip that flips to **“Copied!”** on success.
- **More prominent connection details.** Connection-detail values on the
  site edit page are presented in boxed, higher-contrast chips instead of
  plain inline text.
- Tidied the site-credentials modal: each field's description now sits on
  its own line under the key box, so the “API key” label no longer wraps.

## [1.0.0] — 2026-06-01

First public release. An off-site, zero-knowledge backup server for
[Trusted Servants Pro](https://github.com/hyprlab): TS Pro portals push
their backup archives here over an authenticated HTTP API, and this server
stores them under a grandfather-father-son retention policy with a web
console to manage it all.

### Added

- **End-to-end encryption (default on).** Each site gets its own X25519
  keypair. TS Pro encrypts every archive to the site's **public** key
  before upload using a hybrid `TSPEPK01` envelope (ephemeral X25519 +
  HKDF-SHA256 + streaming AES-256-GCM in 1 MiB blocks). The matching
  **private** key is shown once at site creation and never stored on the
  server, so stored archives are unreadable to the server even if it is
  fully compromised. When `require_e2ee` is on, the upload gate rejects any
  archive that isn't already wrapped in this envelope.
- **Encryption at rest.** Optional defense-in-depth layer over the storage
  volume: streaming AES-256-GCM with PBKDF2-HMAC-SHA256 (600k iterations),
  1 MiB blocks, `TSPENC01` envelope. Server-wide or per-site. Passphrase
  from `TSPB_REST_PASSPHRASE`, or an auto-generated `data/rest.key`.
- **Grandfather-father-son retention.** Keep the newest backup in each of
  the last N distinct days / weeks / months / years, per tier. Runs
  independently **per scope**, so frontend snapshots never evict whole-site
  backups. An all-zero policy keeps everything (no accidental wipe to zero).
- **HTTP API (`/api/v1`).** Per-site API key auth (Bearer / `X-API-Key`),
  CSRF-exempt and stateless. Endpoints: `ping`, single-shot and chunked
  uploads (`backups`, `backups/chunk`, `backups/finalize`), `list`,
  `metadata`, `download`, and `delete` — mirroring TS Pro's existing
  backup-backend interface.
- **Chunked uploads** for archives larger than a fronting proxy's body cap:
  stage chunks by `upload_id`, then reassemble and ingest on finalize.
- **Two backup scopes:** `full` (whole-site export) and `frontend`
  (frontend-only snapshot), retained separately.
- **Web console**, styled to match Trusted Servants Pro: dashboard,
  per-site management with one-time API-key + private-key reveal, and a
  backup browser with download / delete.
- **Cloudflare Turnstile** support on the console login (optional). The
  Turnstile secret is stored encrypted with Fernet (`app/crypto.py`).
- **Additive SQLite migrations** at boot (`_migrate_sqlite()`): missing
  columns are added with `ALTER TABLE ADD COLUMN`, so upgrades are safe
  without Alembic. Fresh installs use `db.create_all()`.
- **Docker deployment.** `python:3.12-slim` image served by gunicorn
  (2 workers, 600s timeout for multi-GB bundles). Data persisted to a
  mounted `/data` volume. Published as
  [`hyprlab/tspro-backup`](https://hub.docker.com/r/hyprlab/tspro-backup).

[1.3.1]: https://github.com/hyprlab/tspro-backup/releases/tag/v1.3.1
[1.3.0]: https://github.com/hyprlab/tspro-backup/releases/tag/v1.3.0
[1.2.1]: https://github.com/hyprlab/tspro-backup/releases/tag/v1.2.1
[1.2.0]: https://github.com/hyprlab/tspro-backup/releases/tag/v1.2.0
[1.1.0]: https://github.com/hyprlab/tspro-backup/releases/tag/v1.1.0
[1.0.2]: https://github.com/hyprlab/tspro-backup/releases/tag/v1.0.2
[1.0.1]: https://github.com/hyprlab/tspro-backup/releases/tag/v1.0.1
[1.0.0]: https://github.com/hyprlab/tspro-backup/releases/tag/v1.0.0
