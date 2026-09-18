# 🔐 Telepathy

> **Anonymous. Encrypted. Ephemeral.**
> A real-time, end-to-end encrypted chat platform built with Django and browser-native RSA/AES cryptography.

---

## 📖 Overview

**Telepathy** is a secure, anonymous chat application where **privacy is guaranteed by design**. Messages are encrypted entirely on the client side using the Web Crypto API before they ever reach the server — meaning the server **never sees plaintext**. Even if the database were compromised, no readable message content would be exposed.

Two parties join a chat room via a shared 4-digit PIN. Once both connect, they exchange messages secured by **hybrid RSA + AES-GCM encryption** and authenticated with a **deniable, ratchet-derived MAC** — verifiable by the chat's other participants, but not provable to anyone outside it. Every encryption step is visible to the user in real-time through a send progress modal and per-message verification badges.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔑 **Per-Chat "Burner" Keys** | A fresh RSA-2048 encryption key pair is generated in the browser for every chat created or joined; private keys never leave the client and are deleted the moment the chat is left |
| 🛡️ **Non-Extractable Private Keys** | Private keys are generated as non-extractable `CryptoKey` objects and stored in IndexedDB, not `localStorage` — even an XSS payload with full JS execution can't export their raw bytes — see [docs/CLIENT_KEY_STORAGE.md](docs/CLIENT_KEY_STORAGE.md) |
| 🔒 **Hybrid Encryption** | AES-256-GCM encrypts the message body; the AES key comes from a forward-secret sending-chain ratchet, not a static wrap — see [docs/FORWARD_SECRECY.md](docs/FORWARD_SECRECY.md) |
| ⏩ **Forward Secrecy** | Each sender's messages are keyed from a one-way HMAC-SHA256 chain (Signal "Sender Key"-style); stealing current key material can't unlock messages sent before that point |
| 🔑 **Key Verification (TOFU)** | Each participant's keys are pinned in the browser the first time they're seen per chat; a later mismatch blocks sending and badges their messages ⚠, and a fingerprint is shown for out-of-band comparison — see [docs/KEY_VERIFICATION.md](docs/KEY_VERIFICATION.md) |
| ⚡ **Real-Time via WebSockets** | New messages and roster changes push instantly over a websocket (Django Channels + Redis), with HTTP polling kept as a slow fallback for reconnect gaps |
| ✍️ **Deniable Authentication** | Every message is authenticated with an HMAC-SHA256 MAC derived from the sender's forward-secrecy ratchet (binding its position in the transcript chain too) — verifiable by the chat's other participants but not provable to a third party, unlike a digital signature. The receiver sees a clickable ✓ Verified badge with full crypto details — see [docs/DENIABLE_AUTH.md](docs/DENIABLE_AUTH.md) |
| 🔗 **Transcript Tamper-Evidence** | Messages are hash-chained; a dropped, reordered, or replayed message breaks a verifiable link instead of being silently trusted |
| 📊 **Send Progress Modal** | An animated progress bar shows each encryption operation in real-time when sending a message |
| 💾 **Encrypted-at-Rest** | Only ciphertext is stored in the database — decryption happens exclusively in the browser |
| 🚫 **No Accounts** | No registration, no password, no persistent identity — a bearer token scoped to one chat is the only credential. See [docs/ACCOUNTLESS_IDENTITY.md](docs/ACCOUNTLESS_IDENTITY.md) for why |
| 📌 **PIN-Based Chat Rooms** | Create or join a room using a 4-digit PIN, freed for reuse once the chat ends |
| 🚫 **Ephemeral History** | Message history is automatically deleted once every participant has left a chat |
| 🎨 **Premium UI** | Dark glassmorphism theme with animated gradients, floating particles, and smooth transitions |

---

## 🏗️ Architecture

```
Telepathy/
├── chat/                       # Main Django application
│   ├── models.py               # User (admin-only), Chat, ChatParticipant, Message, MessageKey, ChainKey, ChainKeyWrap
│   ├── chain.py                 # Transcript hash-chain helper (compute_chain_hash)
│   ├── views.py                # REST API views (create/join chat, send/get messages, etc.)
│   ├── auth.py                 # ParticipantTokenAuthentication -- see docs/ACCOUNTLESS_IDENTITY.md
│   ├── serializers.py          # DRF serializer for Message
│   ├── admin.py                # Django admin registrations
│   ├── urls.py                 # URL routing for the chat app
│   └── templates/
│       ├── index.html          # Landing page (glassmorphism hero + particles)
│       ├── usermenu.html       # Dashboard (create/join chat, no login step)
│       └── chatbox.html        # Chat interface (send modal, verification badges)
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
1. Advance own sending-chain ratchet
   (HMAC-SHA256) to get this
   message's forward-secret key
   and its own MAC auth key
2. Encrypt message with AES-GCM
3. Wrap that key with own                  Stores ONLY:
   RSA-OAEP public key (self-copy)  ───►   • AES-GCM ciphertext
4. MAC seq|prev_hash|chat_id|plaintext      • Self-wrapped key, seq, prev_hash
   with the ratchet-derived auth key        • Nonce, tag, MAC
   (HMAC-SHA256, deniable)
5. POST all fields to API
                                                                     6. GET encrypted messages
                                                                     7. Derive same keys by advancing
                                                                        own cached copy of sender's
                                                                        chain (seeded once via
                                                                        /issue-chain-key/, RSA-OAEP)
                                                                     8. Decrypt message (AES-GCM)
                                                                     9. Verify MAC (HMAC-SHA256)
                                                                    10. Display ✓ Verified badge
```

See [docs/FORWARD_SECRECY.md](docs/FORWARD_SECRECY.md) for why the AES key comes from a ratchet instead of a fresh random key wrapped per recipient.

---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Django 5.1, Django REST Framework |
| **Database** | PostgreSQL (UUID-indexed messages) |
| **Client Crypto** | Web Crypto API (RSA-OAEP, AES-256-GCM, HMAC-SHA256 sending-chain ratchet + deniable MAC) |
| **Server Crypto** | `cryptography` library (PEM key validation) |
| **Frontend** | Vanilla HTML/CSS/JS with glassmorphism design system |

---

## 🚀 Quick Start

> **Prerequisites:** Python 3.10+, PostgreSQL 13+, Redis 6+, Git

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

### 3. Install & start Redis

Required by the real-time (Django Channels) websocket transport -- the app won't start without it.

#### macOS (Homebrew)
```bash
brew install redis
brew services start redis
```

#### Linux/Ubuntu
```bash
sudo apt install redis-server
sudo service redis-server start
```

#### Windows
Redis doesn't officially support Windows; easiest is running it via [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) (follow the Linux/Ubuntu steps above inside it) or a container: `docker run -d -p 6379:6379 redis:7-alpine`.

### 4. Create the database

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

### 5. Set up Python environment & install dependencies

```bash
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows

pip install --upgrade pip
pip install -r requirements.txt
```

### 6. Configure local environment variables

```bash
cp .env.example .env
```

The defaults in `.env.example` already match steps 2–4 above (`DJANGO_SECURE=false`/`DJANGO_DEBUG=true` so the dev server doesn't 301-redirect to HTTPS, plus the DB/Redis host/port this setup uses) -- `pc/settings.py` loads `.env` automatically for a plain local run, so there's nothing else to set unless you changed a default above.

### 7. Apply migrations & start the server

```bash
python manage.py migrate
python manage.py runserver
```

Open **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)** in your browser.

---

## 🧪 Testing the E2E Encryption

> ⚠️ **Important:** You MUST use **two different browsers** (e.g. Chrome + Firefox, or two separate incognito/private windows). Each browser needs its own `localStorage` to store its own per-chat keys and token.

### Step-by-step

1. **Browser A** → `http://127.0.0.1:8000/chat/` → **Create Chat** (optionally enter a display name) → note the 4-digit PIN. No registration or login step — keys are generated and the chat is created in one action.
2. **Browser B** → `http://127.0.0.1:8000/chat/` → **Join Chat** → enter the PIN (and optionally a display name)
3. Both browsers show "Waiting for partner…" briefly, then the chat opens
4. **Send a message** — a progress modal appears showing each encryption step in real-time:
   - Deriving forward-secret session key (ratchet)
   - Encrypting message (AES-256-GCM)
   - Wrapping key for yourself (RSA-OAEP)
   - Authenticating message (deniable MAC)
   - Sending encrypted payload
5. **Receiver** sees the message with a **✓ Verified** badge — click it to see the individual crypto verification steps (chain ratchet, decrypt, MAC verify)
6. **Leave** the chat from either side to end it. If everyone leaves, message history is deleted; each browser's per-chat keys are deleted from that browser's `localStorage` on leave, regardless.

### Group chats (3–8 people)

Instead of **Create Chat**, use **Create Group** on the same landing page: pick a participant limit (2–8) and share the resulting PIN with everyone who should join. Every additional browser/device joins the same way as a 1:1 chat — **Join Chat** with the PIN. Each sender's messages are keyed from their own forward-secret ratchet (see [docs/FORWARD_SECRECY.md](docs/FORWARD_SECRECY.md)), seeded fresh and re-fanned-out to the current roster on every membership change, so a new joiner can't decrypt messages sent before they joined, and a participant who leaves can no longer decrypt anything sent afterward.

---

## 🌐 API Endpoints

All "Participant Token" endpoints authenticate via `Authorization: Token <participant_token>` — a bearer token scoped to one `ChatParticipant`, issued by create-chat/join-chat. See [docs/ACCOUNTLESS_IDENTITY.md](docs/ACCOUNTLESS_IDENTITY.md).

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `GET` | `/chat/usermenu/` | Dashboard (create/join chat) | None |
| `POST` | `/chat/create-chat/` | Create a chat; generates keys client-side first. Returns a 4-digit PIN + participant token | None |
| `POST` | `/chat/join-chat/` | Join an existing chat by PIN; returns a participant token | None |
| `GET` | `/chat/check-chat/<chat_id>/` | Verify chat room exists and list participants | None |
| `GET` | `/chat/get-chat-participants/<chat_id>/` | List active participants' ids/display names/public keys | Participant Token |
| `POST` | `/chat/issue-chain-key/<chat_id>/` | Issue a new forward-secrecy chain epoch, wrapped per current other participant | Participant Token |
| `GET` | `/chat/get-chain-keys/<chat_id>/` | Fetch the latest chain-key epoch issued to you by each sender | Participant Token |
| `POST` | `/chat/send-message/<chat_id>/` | Send an encrypted message | Participant Token |
| `GET` | `/chat/get-messages/<chat_id>/` | Retrieve encrypted messages | Participant Token |
| `POST` | `/chat/leave-chat/` | Leave chat (deletes chat + history once fully empty, freeing its PIN) | Participant Token |

---

## 🗄️ Data Models

### `User` (extends `AbstractUser`)
Exists solely for Django's own admin/staff login. No end-user chat functionality uses this model anymore — see [docs/ACCOUNTLESS_IDENTITY.md](docs/ACCOUNTLESS_IDENTITY.md).

### `Chat`
| Field | Type | Description |
|-------|------|-------------|
| `pin` | `CharField(4)` | Unique 4-digit room code, freed for reuse once every participant leaves (the `Chat` row is hard-deleted, not soft-flagged) |
| `is_group` | `BooleanField` | Whether this chat allows more than 2 participants |
| `max_participants` | `IntegerField` | Capacity (2–8) |

### `ChatParticipant`
A participant's entire identity for exactly one chat — see [docs/ACCOUNTLESS_IDENTITY.md](docs/ACCOUNTLESS_IDENTITY.md) for why this replaced per-account identity.

| Field | Type | Description |
|-------|------|-------------|
| `chat` | `FK(Chat)` | The chat this participation belongs to |
| `display_name` | `CharField` | Self-chosen, chat-scoped only (not globally unique) |
| `public_key` | `TextField` | This chat's freshly generated RSA-OAEP public key (PEM); no signing key -- see [docs/DENIABLE_AUTH.md](docs/DENIABLE_AUTH.md) |
| `auth_token_hash` | `CharField` | SHA-256 hash of the bearer token issued at join time; the raw token is never stored |
| `joined_at` / `left_at` | `DateTimeField` | Presence window; a token stops authenticating once `left_at` is set |

### `Message`
| Field | Type | Description |
|-------|------|-------------|
| `id` | `UUIDField` | UUID primary key |
| `chat` | `FK(Chat)` | Which chat this message belongs to |
| `sender` | `FK(ChatParticipant)` | Who sent it |
| `encrypted_text` | `TextField` | AES-GCM ciphertext (Base64) |
| `aes_nonce` / `aes_tag` | `TextField` | AES-GCM IV and authentication tag |
| `mac` | `TextField` | HMAC-SHA256 tag (Base64), covering `seq\|prev_hash\|chat_id\|plaintext`, keyed from the sender's ratchet -- deniable, see [docs/DENIABLE_AUTH.md](docs/DENIABLE_AUTH.md) |
| `seq` / `prev_hash` | `PositiveIntegerField` / `CharField` | Position in the chat's tamper-evident hash chain (see `chat/chain.py`) |
| `sender_chain_epoch` | `PositiveIntegerField` | Which epoch of the sender's forward-secret ratchet this message's key came from (see [docs/FORWARD_SECRECY.md](docs/FORWARD_SECRECY.md)) |

### `MessageKey`
As of forward secrecy, only ever holds the **sender's own** self-wrapped copy of a message's AES key (so they can always redisplay their own sent history). Other participants derive the key locally from their cached copy of the sender's chain instead of unwrapping a per-message key — see [docs/FORWARD_SECRECY.md](docs/FORWARD_SECRECY.md).

| Field | Type | Description |
|-------|------|-------------|
| `message` | `FK(Message)` | The message this key unlocks |
| `recipient` | `FK(ChatParticipant)` | The sender themself |
| `encrypted_symmetric_key` | `TextField` | The message's AES key, wrapped with the sender's own RSA-OAEP public key |

### `ChainKey` / `ChainKeyWrap`
One epoch of a participant's own sending-chain seed (`ChainKey`), fanned out RSA-OAEP-wrapped per other active participant (`ChainKeyWrap`). A participant issues a new epoch before their first send in a chat, and again whenever the roster has changed since they last did — see [docs/FORWARD_SECRECY.md](docs/FORWARD_SECRECY.md).

| Field | Type | Description |
|-------|------|-------------|
| `ChainKey.sender` | `FK(ChatParticipant)` | Whose sending chain this epoch belongs to |
| `ChainKey.epoch` | `PositiveIntegerField` | Increments each time this sender re-keys |
| `ChainKeyWrap.chain_key` | `FK(ChainKey)` | Which epoch this wrap is for |
| `ChainKeyWrap.recipient` | `FK(ChatParticipant)` | Who this wrapped seed is for |
| `ChainKeyWrap.encrypted_seed` | `TextField` | The 32-byte chain seed, RSA-OAEP-wrapped (Base64) |

---

## 🔧 Environment Variables

The same variables apply whether you're deploying to production or running locally via `.env` (see Quick Start step 6 -- `pc/settings.py` loads `.env` automatically, so these are also how you configure a plain local run, not just a production deployment):

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
| `REDIS_HOST` | Redis host (Channels' websocket channel layer) | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `ONION_HOSTNAME` | Set once a Tor hidden-service `.onion` address exists (see below) | unset |

---

## 🧅 Running as a Tor Hidden Service (Podman)

This runs the whole stack — app, Postgres, and a Tor hidden service in front of it — in containers, so the server's hosting location is never exposed and connecting users' real IPs never reach the app either (a Tor onion service has no exit node; traffic stays inside the Tor network end-to-end). Uses [Podman](https://podman.io/) (rootless, no root daemon) rather than Docker, via `podman-compose` (same compose schema as Docker Compose).

**Before you start:** two settings are easy to get backwards and will silently break the deployment if you do:
- **`DJANGO_SECURE` must stay `false`.** Tor's onion transport already provides end-to-end encryption and server authentication (the `.onion` address *is* the server's public key) — there's no TLS certificate for an onion address, so turning on `SECURE_SSL_REDIRECT`/HSTS/secure-cookies breaks the plain-HTTP hop between Tor and the app for no benefit.
- **No container in `compose.yaml` publishes a port to the host.** The only path in is through the `tor` container, which shares the `app` container's network namespace. If you find yourself adding a `ports:` mapping to reach it directly, that defeats the point.

### Steps

1. Copy `.env.example` to `.env` and fill in `DJANGO_SECRET_KEY`/`DB_PASSWORD` (leave `ONION_HOSTNAME` blank for now).
2. `podman-compose up --build` — starts `db`, `redis` (Channels' websocket layer), `app` (migrates + collects static + daphne on `127.0.0.1:8000`, not published), and `tor` (which shares `app`'s network namespace and proxies port 80 on the hidden service to it).
3. Wait for the `tor` container's logs to show `Bootstrapped 100%`, then read the generated address:
   ```
   podman exec <tor-container-name> cat /var/lib/tor/telepathy_hidden_service/hostname
   ```
4. Set `ONION_HOSTNAME` in `.env` to that value and restart the stack (`podman-compose up -d`) so it's accepted by `ALLOWED_HOSTS`. This needs the whole stack, not just `app` — `tor` shares `app`'s network namespace, so Podman won't recreate one without the other.
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

This project is licensed under the [MIT License](./LICENSE).

**Please use it responsibly.** Telepathy is an educational project for learning and demonstrating applied cryptography and secure system design — it has not undergone a professional, independent security audit. Do not rely on it to protect communications where real safety, legal, or financial consequences depend on its correctness, and do not use it for any unlawful purpose.
