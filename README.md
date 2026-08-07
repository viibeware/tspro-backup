<p align="center">
  <img src="app/static/img/logo_tspro_white.svg" alt="TS Pro Backup" width="320">
</p>

<h1 align="center">TS Pro Backup</h1>

<p align="center">Off-site, encrypted backup storage for Trusted Servants Pro.</p>

<p align="center">
  <a href="https://hub.docker.com/r/hyprlab/tspro-backup"><img alt="Docker Image" src="https://img.shields.io/docker/v/hyprlab/tspro-backup?label=docker&sort=semver"></a>
  <a href="https://hub.docker.com/r/hyprlab/tspro-backup"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/hyprlab/tspro-backup"></a>
  <a href="LICENSE"><img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-blue"></a>
</p>

---

TS Pro Backup is a small, self-hostable server you deploy **off-site** from
your Trusted Servants Pro portal. Each portal ("site") connects to this
server's API with its own key and pushes backup archives here. The server
stores them — optionally **AES-256 encrypted at rest** — enforces a
**grandfather-father-son retention policy**, and gives you a clean web
console (matching the TS Pro look) to manage sites and browse backups.

It receives two kinds of archive from TS Pro:

- **Whole-site backups** (`full`) — the complete portal export: SQLite DB
  + uploads + encryption key seed.
- **Frontend-only backups** (`frontend`) — just the public web frontend.

Retention runs independently per scope, so a burst of frontend snapshots
never evicts your whole-site backups.

## Features

- 🔑 **End-to-end encrypted** (default on) — every site gets its own
  X25519 keypair. TS Pro encrypts each backup to the site's **public**
  key before upload; only the **private** key (shown once at site
  creation, never stored here) can decrypt it. The server holds only
  ciphertext, so it can't read your backups even if fully compromised,
  and the API rejects any upload that isn't already encrypted.
- 🔒 **Hardened console login** — brute-force lockout (per username and IP),
  a forced first-login password change (no standing `admin/admin`), and
  session invalidation on password change.
- 👥 **Admin / user roles** — `admin` accounts have full access; `user`
  accounts manage sites and backups but can't rotate keys, delete sites, or
  change a site's encryption policy.
- 🔐 **Cloudflare Turnstile** on the console login (optional).
- 🛡️ **Hardened by default** — non-root container, secure response headers
  (CSP, HSTS, `X-Frame-Options`, …), `0600` data files, server-enforced
  upload size/quota caps, and an envelope-structure check on every E2EE
  upload.
- 🧱 **Encrypted at rest** — streaming AES-256-GCM, server-wide or
  per-site. Defense-in-depth for the storage volume with a key the
  *server* holds, so it is **not** end-to-end; independent of the E2EE
  layer above (with E2EE on, the bytes are already opaque to us).
- 🗓️ **GFS retention** — keep N recent days / weeks / months / years.
- 🌐 **HTTP API** that mirrors TS Pro's existing backup-backend interface
  (`put / list / delete / fetch`), so wiring up a "TS Pro Backup" target
  in TS Pro is a thin client. Single-shot **and** chunked uploads for
  multi-GB bundles behind a proxy body cap.
- 🎛️ **Web console** — dashboard, per-site API keys, backup browser with
  download/delete, all styled to match Trusted Servants Pro.

## Deploy with Docker Compose

The recommended way to run TS Pro Backup. You need [Docker](https://docs.docker.com/get-docker/)
with the Compose plugin — nothing else.

### 1. Get the compose file

Either clone the repo:

```bash
git clone https://github.com/hyprlab/tspro-backup.git
cd tspro-backup
```

…or, if you'd rather not clone, just create a `docker-compose.yml` next to
a `data/` directory with this content (it pulls the published image — no
source checkout needed):

```yaml
services:
  tspro-backup:
    image: hyprlab/tspro-backup:latest
    container_name: tspro-backup
    ports:
      - "${TSPB_PORT:-8095}:8000"
    volumes:
      - ./data:/data
    environment:
      - TSPB_SECRET_KEY=${TSPB_SECRET_KEY:?TSPB_SECRET_KEY must be set in .env}
      - TSPB_ADMIN_USERNAME=${TSPB_ADMIN_USERNAME:-admin}
      - TSPB_ADMIN_PASSWORD=${TSPB_ADMIN_PASSWORD:-admin}
      - TSPB_REST_PASSPHRASE=${TSPB_REST_PASSPHRASE:-}
      - TSPB_MAX_UPLOAD_MB=${TSPB_MAX_UPLOAD_MB:-8192}
      - TSPB_DEBUG=${TSPB_DEBUG:-0}
    restart: unless-stopped
```

### 2. Configure the environment

```bash
cp .env.example .env
```

The full sample `.env` looks like this:

```ini
# Copy to .env and fill in. Generate a strong secret:
#   python -c "import secrets; print(secrets.token_urlsafe(48))"
TSPB_SECRET_KEY=change-me-to-a-long-random-string

# Seed admin (used only on first boot, when the DB is empty).
TSPB_ADMIN_USERNAME=admin
TSPB_ADMIN_PASSWORD=admin

# Host port to expose the console on (the container always listens on
# 8000 internally).
TSPB_PORT=8095

# Optional at-rest encryption passphrase. If set, reproducible across
# rebuilds; if blank, a random key is generated in ./data/rest.key.
TSPB_REST_PASSPHRASE=

# Max single upload in MiB (whole-site bundles can be large).
TSPB_MAX_UPLOAD_MB=8192

# Console sign-in lockout. After this many failed attempts for one username
# OR one client IP within the window (minutes), sign-ins are refused until
# the oldest failures age out. Set FAILURES to 0 to disable.
TSPB_LOGIN_MAX_FAILURES=5
TSPB_LOGIN_WINDOW_MINUTES=15

# Set to 1 only for local HTTP dev (disables Secure cookie flag).
TSPB_DEBUG=0

# Trust X-Forwarded-* from the proxy in front. Leave at 1 ONLY when a trusted
# reverse proxy is the sole ingress and overwrites X-Forwarded-For. If the
# container port is reachable directly, set to 0 (uses the real socket peer)
# so the login lockout can't be defeated by a spoofed X-Forwarded-For.
TSPB_TRUST_PROXY=1
```

At minimum, set a strong session secret and change the admin password:

```bash
# Generate a strong secret:
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

```ini
TSPB_SECRET_KEY=<paste the generated secret>
TSPB_ADMIN_PASSWORD=<a strong password>
```

### 3. Start it

```bash
docker compose up -d
```

The first boot creates the seed admin and initializes the database in
`./data`. Open the console at **<http://localhost:8095>** and sign in with
`TSPB_ADMIN_USERNAME` / `TSPB_ADMIN_PASSWORD`.

Check logs / status any time:

```bash
docker compose logs -f
docker compose ps
```

### 4. First-run setup in the console

0. **Sign in** with the seed credentials. If the admin password is still the
   default `admin`, the console walks you through a one-time password change
   before anything else is reachable.
1. **Settings** → end-to-end encryption is required by default; optionally
   enable Turnstile, encryption at rest, and set the default retention.
2. **Sites → Add site** → name it. Copy the **API key** *and* the
   **private key** shown once — store the private key somewhere safe.
3. In your TS Pro portal, add a **TS Pro Backup** target pointing at
   `https://<this-host>/api/v1` with that API key; it fetches the site's
   public key automatically and encrypts every backup to it.

> ⚠️ The **private key** is the only thing that can decrypt your backups,
> and this server never keeps a copy. Lose it and the stored archives are
> **permanently unrecoverable** — that's what makes the storage
> zero-knowledge. Keep it in a password manager.

### 5. Put TLS in front of it

The console sets `Secure` session cookies, so in production it must be
served over HTTPS. Terminate TLS at a reverse proxy (Caddy, nginx,
Traefik, Cloudflare Tunnel, …) in front of the container — for example,
proxy `https://backup.example.org` → `http://127.0.0.1:8095`. Make sure
the proxy's max request body size is large enough for your whole-site
bundles (or rely on the chunked upload endpoints). Leave `TSPB_DEBUG=0`
behind TLS; set it to `1` **only** for local plain-HTTP development.

The app trusts `X-Forwarded-*` from the proxy by default (`TSPB_TRUST_PROXY=1`),
which is correct when a trusted proxy is the **only** way in. If the container
port is also reachable directly, either bind it to loopback
(`127.0.0.1:8095:8000`) or set `TSPB_TRUST_PROXY=0`, so a spoofed
`X-Forwarded-For` can't defeat the per-IP login lockout.

### Upgrading

```bash
docker compose pull          # fetch the new image
docker compose up -d         # recreate the container
```

Your data lives in the `./data` volume and is preserved across upgrades.
Schema changes are applied automatically at boot (additive SQLite
migrations), so no manual migration step is needed.

> **Upgrading to 1.1.0** has three one-time effects: existing console
> sessions are invalidated (sign in again); an admin still on the `admin`
> password is sent through a forced change wizard; and a site with E2EE
> required but no key must have its keypair rotated before it can upload.

### Build from source instead

To build the image locally rather than pulling it, uncomment `build: .`
in `docker-compose.yml` and run `docker compose up -d --build`.

## Run locally (without Docker)

For development:

```bash
pip install -r requirements.txt
TSPB_SECRET_KEY=dev-secret TSPB_DEBUG=1 python run.py
```

Serves on <http://localhost:8000> with plain-HTTP dev cookies.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `TSPB_SECRET_KEY` | — (required) | Flask session secret. |
| `TSPB_PORT` | `8095` | Host port for the console (compose only). |
| `TSPB_FERNET_KEY` | auto (`data/secret.key`) | Seed for encrypting the Turnstile secret. |
| `TSPB_REST_PASSPHRASE` | auto (`data/rest.key`) | At-rest encryption passphrase. |
| `TSPB_ADMIN_USERNAME` / `TSPB_ADMIN_PASSWORD` | `admin` / `admin` | Seed admin (first boot only). Default password forces a change on first login. |
| `TSPB_DATA_DIR` | `/data` | Where the DB + archives live. |
| `TSPB_MAX_UPLOAD_MB` | `8192` | Max backup size (single-shot or reassembled). |
| `TSPB_SITE_QUOTA_MB` | `0` (off) | Optional per-site storage quota. |
| `TSPB_TRUST_PROXY` | `1` | Trust `X-Forwarded-*`. Set `0` if the port is reachable without a trusted proxy. |
| `TSPB_LOGIN_MAX_FAILURES` | `5` | Failed sign-ins (per username/IP) before lockout; `0` disables. |
| `TSPB_LOGIN_WINDOW_MINUTES` | `15` | Sliding lockout window. |
| `TSPB_DEBUG` | `0` | `1` = plain-HTTP dev cookies. |
| `TSPB_FLASK_DEBUG` | `0` | `1` = Werkzeug debugger (loopback dev only). |

> ⚠️ If you rely on at-rest encryption, **back up `TSPB_REST_PASSPHRASE`
> (or `data/rest.key`)**. Losing it makes the stored archives
> unrecoverable — by design.

## API

Authenticate every request with `Authorization: Bearer <key>` (or
`X-API-Key: <key>`).

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/ping` | Auth check + capabilities. |
| `POST` | `/api/v1/backups` | Upload (`file`, `scope`, optional `note`). |
| `POST` | `/api/v1/backups/chunk` | One chunk of a large upload (`upload_id`, `chunk_index`, `total_chunks`, `chunk`). |
| `POST` | `/api/v1/backups/finalize` | Reassemble chunks + store (`upload_id`, `scope`, `filename`, `total_chunks`). |
| `GET` | `/api/v1/backups` | List this site's backups (`?scope=`). |
| `GET` | `/api/v1/backups/<id>` | One backup's metadata. |
| `GET` | `/api/v1/backups/<id>/download` | Download original bytes. |
| `DELETE` | `/api/v1/backups/<id>` | Delete one backup. |

Example upload:

```bash
curl -H "Authorization: Bearer tspb_XXXX" \
     -F scope=full -F file=@tsp-export-20260531-030000.zip \
     https://backup.example.org/api/v1/backups
```

## Data & backups of the backup server

Everything stateful lives under `./data`:

- `tspro_backup.db` — sites, settings, backup metadata.
- `storage/site-<id>/` — the stored archive blobs.
- `rest.key` / `secret.key` — auto-generated keys (if you didn't supply
  your own via env). **These are secrets** — protect the volume, and if
  you copy `data/` elsewhere you copy the keys with it.

To migrate hosts, stop the container and copy the whole `data/` directory.

## Versioning & releases

This project follows [Semantic Versioning](https://semver.org). See
[CHANGELOG.md](CHANGELOG.md) for the full history and the
[releases page](https://github.com/hyprlab/tspro-backup/releases) for
release notes. Images are published to
[`hyprlab/tspro-backup`](https://hub.docker.com/r/hyprlab/tspro-backup)
tagged by version (e.g. `1.0.0`) and `latest`.

## AI notice

TS Pro Backup is built by a human maintainer working with generative AI as a development tool:

- **Code** — the large majority of the Python code in this repository was written with Anthropic's Claude (via Claude Code), working from the maintainer's direction. The maintainer decides what gets built, reviews the results, tests every release, and signs off on everything that ships.
- **Text** — documentation, release notes, and in-app copy are largely AI-drafted and human-edited.
- **The app itself contains no AI.** The backup server has no AI features and makes no requests to AI services — your backups are stored and served from your own host only. AI was used to *build* the app, not to run it.

Bug reports and pull requests are welcome from humans and their AI tools alike; everything merged gets the same human review.

## License

[AGPL-3.0-or-later](LICENSE).
