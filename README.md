# 🔐 Telepathy

> **Anonymous. Encrypted. Ephemeral.**
> A real-time, end-to-end encrypted chat platform built with Django and browser-native RSA/AES cryptography.

---

## 📖 Overview

**Telepathy** is a secure, anonymous chat application where **privacy is guaranteed by design**. Messages are encrypted entirely on the client side using the Web Crypto API before they ever reach the server — meaning the server **never sees plaintext**. Even if the database were compromised, no readable message content would be exposed.

Two parties join a chat room via a shared 4-digit PIN. Once both connect, they exchange messages secured by **hybrid RSA + AES-GCM encryption** and verified with **RSA-PSS digital signatures**. Every encryption step is visible to the user in real-time through a send progress modal and per-message verification badges.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔑 **Client-Side Key Generation** | Two RSA-2048 key pairs (encryption + signing) are generated in the browser at registration; private keys never leave the client |
| 🔒 **Hybrid Encryption** | AES-256-GCM encrypts the message body; RSA-OAEP wraps the AES key for both sender and receiver |
| ✍️ **Digital Signatures** | Every message is signed with RSA-PSS — the receiver sees a clickable ✓ Verified badge with full crypto details |
| 📊 **Send Progress Modal** | A 6-step animated progress bar shows each encryption operation in real-time when sending a message |
| 💾 **Encrypted-at-Rest** | Only ciphertext is stored in the database — decryption happens exclusively in the browser |
| 📌 **PIN-Based Chat Rooms** | No email required; create or join a room using a 4-digit PIN |
| 🛡️ **Two-Factor Authentication** | Optional TOTP 2FA via QR code and authenticator app (e.g. Google Authenticator) |
| 🚫 **Ephemeral History** | Message history is automatically deleted when a user leaves the chat |
| 🔐 **Token + Session Auth** | DRF Token authentication for API calls; Django sessions for page access; server-side logout invalidates tokens |
| 🎨 **Premium UI** | Dark glassmorphism theme with animated gradients, floating particles, and smooth transitions |

---

## 🏗️ Architecture

```
Telepathy/
├── chat/                       # Main Django application
│   ├── models.py               # User, Chat, Message models
│   ├── views.py                # REST API views (register, login, send/get messages, etc.)
│   ├── serializers.py          # DRF serializers for User and Message
│   ├── admin.py                # Django admin registrations
│   ├── urls.py                 # URL routing for the chat app
│   └── templates/
│       ├── index.html          # Landing page (glassmorphism hero + particles)
│       ├── auth.html           # Register + Login (crypto log panel)
│       ├── usermenu.html       # Dashboard (create/join chat, PIN modal)
│       ├── chatbox.html        # Chat interface (send modal, verification badges)
│       └── chat/
│           └── 2fa_setup.html  # TOTP two-factor authentication setup
├── pc/                         # Django project configuration
│   ├── settings.py             # App settings (env-driven secrets, DB, security)
│   ├── urls.py                 # Root URL configuration
│   └── asgi.py                 # ASGI entrypoint
├── manage.py
└── requirements.txt
```

### Encryption Flow

```
SENDER (Browser A)                          SERVER                    RECEIVER (Browser B)
──────────────────                          ──────                    ────────────────────
1. Generate random AES-256 key
2. Encrypt message with AES-GCM
3. Wrap AES key with Receiver's            Stores ONLY:
   RSA-OAEP public key              ───►   • AES-GCM ciphertext
4. Wrap AES key with own                    • Wrapped keys (2x)
   RSA-OAEP public key                     • Nonce, tag, signature
5. Sign plaintext with RSA-PSS
6. POST all fields to API
                                                                     7. GET encrypted messages
                                                                     8. Unwrap AES key (RSA-OAEP)
                                                                     9. Decrypt message (AES-GCM)
                                                                    10. Verify signature (RSA-PSS)
                                                                    11. Display ✓ Verified badge
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Django 5.1, Django REST Framework |
| **Database** | PostgreSQL (UUID-indexed messages) |
| **Client Crypto** | Web Crypto API (RSA-OAEP, RSA-PSS, AES-256-GCM) |
| **Server Crypto** | `cryptography` library (PEM key validation) |
| **2FA** | `pyotp` (TOTP) + `qrcode` |
| **Frontend** | Vanilla HTML/CSS/JS with glassmorphism design system |

---

## 🚀 Quick Start

> **Prerequisites:** Python 3.10+, PostgreSQL 13+, Git

### 1. Clone & enter the project

```bash
git clone https://github.com/sinan-can-demir/Telepathy.git
cd Telepathy
```

### 2. Install & start PostgreSQL

#### macOS (Homebrew)
```bash
brew install postgresql@17
brew services start postgresql@17
```

#### Linux/Ubuntu
```bash
sudo apt install postgresql postgresql-contrib
sudo service postgresql start
```

#### Windows
Download from [postgresql.org/download](https://www.postgresql.org/download/).

### 3. Create the database

```bash
# Open a PostgreSQL shell
psql -d postgres           # macOS/Linux
psql -U postgres            # Windows
```

Then run:

```sql
CREATE ROLE myproject_user
  WITH LOGIN PASSWORD 'mysecretpassword'
  CREATEDB CREATEROLE INHERIT;

CREATE DATABASE my_database
  OWNER = myproject_user
  ENCODING = 'UTF8'
  TEMPLATE = template0;

\q
```

> **Tip (macOS):** If `psql` asks for a password and you don't know it, change `/opt/homebrew/var/postgresql@17/pg_hba.conf` — replace `md5` or `scram-sha-256` with `trust` in all local lines, then run `brew services restart postgresql@17`.

### 4. Set up Python environment & install dependencies

```bash
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows

pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Apply migrations & start the server

```bash
python manage.py migrate
python manage.py runserver
```

Open **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)** in your browser.

---

## 🧪 Testing the E2E Encryption

> ⚠️ **Important:** You MUST use **two different browsers** (e.g. Chrome + Firefox, or two separate incognito/private windows). Each browser needs its own `localStorage` to store separate user keys and tokens.

### Step-by-step

1. **Browser A** → `http://127.0.0.1:8000/chat/` → Register as `alice` → Login → **Create Chat** → note the 4-digit PIN
2. **Browser B** → `http://127.0.0.1:8000/chat/` → Register as `bob` → Login → **Join Chat** → enter Alice's PIN
3. Both browsers show "Waiting for partner…" briefly, then the chat opens
4. **Send a message** — a progress modal appears showing all 6 encryption steps in real-time:
   - Generating AES-256 session key
   - Encrypting message (AES-256-GCM)
   - Wrapping key for partner (RSA-OAEP)
   - Wrapping key for self (RSA-OAEP)
   - Signing message (RSA-PSS)
   - Sending encrypted payload
5. **Receiver** sees the message with a **✓ Verified** badge — click it to see the individual crypto verification steps (key unwrap, decrypt, signature verify)

---

## 🌐 API Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/chat/register/` | Create account + upload both public keys | None |
| `POST` | `/chat/login/` | Authenticate and receive a DRF token | None |
| `POST` | `/chat/logout/` | Invalidate token and clear server session | Token |
| `GET` | `/chat/usermenu/` | User dashboard | Session |
| `POST` | `/chat/create-chat/` | Generate a new 4-digit chat PIN | Token |
| `POST` | `/chat/join-chat/` | Join an existing chat by PIN | Token |
| `GET` | `/chat/check-chat/<chat_id>/` | Verify chat room exists and participants | Token |
| `POST` | `/chat/send-message/<chat_id>/` | Send an encrypted message | Token |
| `GET` | `/chat/get-messages/<chat_id>/` | Retrieve encrypted messages | Token |
| `GET` | `/chat/get-public-key/<user_id>/` | Fetch user's encryption + signing public keys | Token |
| `POST` | `/chat/upload-public-key/` | Upload/update caller's public keys | Token |
| `POST` | `/chat/leave-chat/` | Leave chat (deletes message history) | Token |
| `GET/POST` | `/chat/2fa/setup/` | Set up TOTP two-factor authentication | Session |

---

## 🗄️ Data Models

### `User` (extends `AbstractUser`)
| Field | Type | Description |
|-------|------|-------------|
| `totp_secret` | `CharField` | TOTP secret for 2FA (never exposed via API) |
| `is_2fa_enabled` | `BooleanField` | Whether 2FA is active |
| `public_key` | `TextField` | RSA-OAEP public key for encryption (PEM) |
| `signing_public_key` | `TextField` | RSA-PSS public key for signature verification (PEM) |

### `Chat`
| Field | Type | Description |
|-------|------|-------------|
| `pin` | `CharField(4)` | Unique 4-digit room code |
| `user1` | `FK(User)` | Chat creator |
| `user2` | `FK(User)` | Chat joiner |
| `is_active` | `BooleanField` | Whether the room is active |

### `Message`
| Field | Type | Description |
|-------|------|-------------|
| `id` | `UUIDField` | UUID primary key |
| `sender` / `receiver` | `FK(User)` | Message parties |
| `encrypted_text` | `TextField` | AES-GCM ciphertext (Base64) |
| `encrypted_symmetric_key` | `TextField` | AES key wrapped with receiver's RSA public key |
| `sender_encrypted_symmetric_key` | `TextField` | AES key wrapped with sender's own RSA public key |
| `aes_nonce` / `aes_tag` | `TextField` | AES-GCM IV and authentication tag |
| `signature` | `TextField` | RSA-PSS digital signature (Base64) |

---

## 🔧 Environment Variables (Production)

When deploying to production, set these environment variables instead of editing source code:

| Variable | Description | Default |
|----------|-------------|---------|
| `DJANGO_SECRET_KEY` | Django secret key | Insecure dev fallback |
| `DJANGO_DEBUG` | Set to `true` to enable debug mode locally | `false` (fails closed) |
| `DJANGO_SECURE` | Set to `false` to disable HTTPS-only cookies/HSTS for local HTTP dev | `true` (fails closed) |
| `DB_NAME` | PostgreSQL database name | `my_database` |
| `DB_USER` | PostgreSQL user | `myproject_user` |
| `DB_PASSWORD` | PostgreSQL password | `mysecretpassword` |
| `DB_HOST` | Database host | `localhost` |
| `DB_PORT` | Database port | `5432` |
| `ONION_HOSTNAME` | Set once a Tor hidden-service `.onion` address exists (see below) | unset |

---

## 🧅 Running as a Tor Hidden Service (Podman)

This runs the whole stack — app, Postgres, and a Tor hidden service in front of it — in containers, so the server's hosting location is never exposed and connecting users' real IPs never reach the app either (a Tor onion service has no exit node; traffic stays inside the Tor network end-to-end). Uses [Podman](https://podman.io/) (rootless, no root daemon) rather than Docker, via `podman-compose` (same compose schema as Docker Compose).

**Before you start:** two settings are easy to get backwards and will silently break the deployment if you do:
- **`DJANGO_SECURE` must stay `false`.** Tor's onion transport already provides end-to-end encryption and server authentication (the `.onion` address *is* the server's public key) — there's no TLS certificate for an onion address, so turning on `SECURE_SSL_REDIRECT`/HSTS/secure-cookies breaks the plain-HTTP hop between Tor and the app for no benefit.
- **No container in `compose.yaml` publishes a port to the host.** The only path in is through the `tor` container, which shares the `app` container's network namespace. If you find yourself adding a `ports:` mapping to reach it directly, that defeats the point.

### Steps

1. Copy `.env.example` to `.env` and fill in `DJANGO_SECRET_KEY`/`DB_PASSWORD` (leave `ONION_HOSTNAME` blank for now).
2. `podman-compose up --build` — starts `db`, `app` (migrates + collects static + gunicorn on `127.0.0.1:8000`, not published), and `tor` (which shares `app`'s network namespace and proxies port 80 on the hidden service to it).
3. Wait for the `tor` container's logs to show `Bootstrapped 100%`, then read the generated address:
   ```
   podman exec <tor-container-name> cat /var/lib/tor/telepathy_hidden_service/hostname
   ```
4. Set `ONION_HOSTNAME` in `.env` to that value and recreate the `app` service (`podman-compose up -d --build app`) so it's accepted by `ALLOWED_HOSTS`.
5. Connect to the printed `.onion` address using Tor Browser.

The hidden service's private key lives in the `tor_data` named volume — **that's the one piece of state in this stack that must persist**; deleting it changes the `.onion` address. Everything else (`app`, `db`'s actual rows) can be recreated freely.

If your `podman-compose` version doesn't support the `network_mode: "service:app"` syntax used in `compose.yaml`, the fallback is a native Podman pod (`podman pod create`) with both containers attached to it instead — same effect, different plumbing.

---

## 🧹 Stopping & Cleanup

### Stop the server

Press `Ctrl+C` in the terminal running `manage.py runserver`.

### Stop PostgreSQL

```bash
# macOS
brew services stop postgresql@17

# Linux
sudo service postgresql stop
```

### Delete the database and role

```bash
psql -d postgres -c "DROP DATABASE IF EXISTS my_database;"
psql -d postgres -c "DROP ROLE IF EXISTS myproject_user;"
```

### Remove the virtual environment

```bash
deactivate                  # exit the venv first
rm -rf venv/
```

### Reset everything (keep the database but wipe all data)

```bash
source venv/bin/activate
python manage.py flush --no-input
```

---

## 🕰️ Legacy / Fork Notice

This repository was originally created by other contributors (the commit history predates this fork and includes the original "pentour" project). It has since been forked and is now actively maintained here, independently of the original repo.

**If you have questions, bug reports, or want to contribute going forward, please reach out via this fork rather than the original repository or its original contact email.**

---

## 🤝 Contributing

Contributions are welcome! Please read [ContributorGuide.md](./ContributorGuide.md) for details on the project structure, where to place static files, and Git workflow conventions.

Before proposing a feature that touches chat/message data, read [ARCHITECTURE.md](./ARCHITECTURE.md) — it documents known structural limitations (e.g. the PIN space, message-to-chat linkage) that will affect how new features should be designed.

---

## 📬 Contact

For bugs, questions, or setup issues, reach out via GitHub:

👤 **[@sinan-can-demir](https://github.com/sinan-can-demir)**

---

## 📄 License

This project is for academic use. Please contact the author before using it in production or redistributing.
