# Architecture Notes & Known Limitations

This document captures the results of an architecture review of the current codebase — not a security audit (see the closed/open security issues in the tracker for that), but an assessment of whether the foundation can support future features without a rewrite.

## Verdict

The crypto/API layer is solid: end-to-end encryption, transcript tamper-evidence (hash-chained messages), forward secrecy (a per-sender HMAC ratchet), TOFU key verification, and hardened client-side key storage (non-extractable `CryptoKey`s in IndexedDB) are all in place — see `docs/ACCOUNTLESS_IDENTITY.md`, `docs/FORWARD_SECRECY.md`, `docs/KEY_VERIFICATION.md`, and `docs/CLIENT_KEY_STORAGE.md`. The structural data-model problems that used to block group chat and long-term PIN availability are both resolved, and the transport layer now pushes new messages/roster changes over a websocket instead of relying solely on polling. What's left is mostly about *how the code is organized* rather than what it's missing: no service layer (domain logic still lives in view methods).

## Known limitations, ranked by how much they block future work

### 1. ~~`Message` has no foreign key to `Chat`~~ — Resolved

`Message.chat` is a real foreign key (`chat/models.py`), and `GetMessagesView`/`SendMessageView` query through `chat.messages` rather than inferring conversation identity from a `(sender, receiver)` pair. This was the prerequisite for group chat, which now exists (`ChatParticipant`, `docs/GROUP_CHATS_PLAN.md`).

### 2. ~~The 4-digit PIN space (10,000 values) is never recycled~~ — Resolved

`LeaveChatView` now hard-deletes the `Chat` row once every participant has left (cascading to its `ChatParticipant`/`Message`/`MessageKey`/`ChainKey` rows), instead of soft-flagging it with `is_active=False` forever. `Chat.pin`'s uniqueness constraint only applies to chats that still exist, so an ended chat's PIN is immediately available for a new chat to reuse (#35).

### 3. ~~`active_chats` in-process dict is dead code today, a landmine tomorrow~~ — Resolved

Removed entirely as part of the Phase 1 group-chat schema migration. If presence/online-status is wanted later, it belongs in Postgres (`ChatParticipant.left_at`, or the fact that a `Chat` row exists at all now that ended chats are hard-deleted) or Redis, not a per-process dict.

### 4. ~~Polling transport is a reasonable MVP choice, but `channels` is a half-installed illusion~~ — Resolved

`pc/asgi.py` now routes through a real `ProtocolTypeRouter`, `chat/consumers.py` and `chat/routing.py` exist, and `CHANNEL_LAYERS` uses a Redis backend (`channels_redis`). `SendMessageView`/`JoinChatView`/`LeaveChatView` push a lightweight signal (`chat/realtime.py`'s `notify_chat`) over the chat's websocket group on every new message or roster change, and the client (`chatbox.html`) immediately re-runs its existing HTTP fetch on receiving one instead of waiting for the next poll tick — HTTP polling is kept, just slowed to a 15s fallback for reconnect gaps, per issue #37's own "additive, don't remove the REST endpoints" direction. Production now runs `daphne` (an ASGI server) instead of `gunicorn` (WSGI-only, can't serve websocket upgrades at all), and `compose.yaml` gained a `redis` service.

One dependency note worth keeping in mind going forward: `channels_redis==4.2.1` has no upper bound on its own `redis` dependency, so a plain `pip install` pulls `redis>=8`, which has real async timeout/connection-pool incompatibilities with it (reproduced locally — the channel layer's background listener crashed with a spurious `redis.exceptions.TimeoutError` under load). `requirements.txt` pins `redis==5.0.8` explicitly to avoid this; don't let that pin drift without re-testing against whatever `channels_redis` version is current at the time.

### 5. ~~Chat identity is tracked in two places that can disagree~~ — Resolved

The server used to also stash `chat_id` in the Django session (read by the page-rendering `chatbox` view), duplicating what the frontend JS already tracked in `localStorage`. The `chatbox` view no longer reads or writes any session state — `localStorage` (used by every fetch-based API call) is the sole source of truth for "what chat is this browser currently in."

### 6. Fat views, no service layer

Chat-pairing logic (slot assignment, message cleanup on leave, chain-key issuance) lives directly inside `APIView.post`/`get` methods in `chat/views.py`, mixing HTTP status-code decisions with domain rules. There's no `chat/services.py` or model-level methods (e.g. `Chat.add_participant(user)`) to unit-test independent of DRF request/response plumbing — every test of pairing/leave/visibility logic currently has to go through a full `APIClient` HTTP round trip (tracked as issue #39).

**Direction**: extract pairing/leave/messaging rules into plain functions or model methods that views call into. Lets core chat rules be tested in milliseconds without spinning up the request/response cycle, and makes it easier to compose new behavior (e.g. "notify partner on join") without re-editing the view.

## What's already solid and doesn't need to change

- **Serializers** (`chat/serializers.py`) are clean, idiomatic DRF `ModelSerializer`s — no manual dict construction creeping into view logic.
- **Indexing** on `Message` (`chat`, `sender`, `timestamp`, plus a composite `(chat, -timestamp)` index, and a `unique_together (chat, seq)` for the transcript chain) is well-matched to the actual polling query pattern.
- **Client/server crypto boundary** is genuinely clean: the server only ever touches ciphertext, PEM blobs, and wrapped seeds, never plaintext or private key material. This API surface is pure JSON + token auth and could be reused as-is by a future mobile app or SPA.
- **UUID primary key on `Message`** avoids sequential-ID enumeration and is a reasonable choice if message data is ever synced or sharded.
- The split between page-rendering views and JSON API views is at least consistently named.
- The inline-script frontend approach isn't a crisis at the current scope — no framework is needed for a single-page polling chat — but it's already showing strain (`chatbox.html` now carries the transcript chain, the ratchet, and the send/receive UI all in one file) and will need extraction into modules before another screen's worth of UI logic is added.

## Identity model: accounts removed in favor of per-chat participants

Every chat participant used to be a persistent Django `User` (username/password/optional TOTP), reused across every chat that account ever joined. Because `ChatParticipant.user` and `Message.sender` both pointed at that one durable row, the database could already correlate "this account was in chat A, B, and C" even though message *content* stayed encrypted — a cross-chat linkability vector at odds with the app's own anonymous/ephemeral positioning.

Accounts, passwords, and 2FA have been removed entirely. `ChatParticipant` is now a free-standing identity scoped to exactly one chat — its own display name, its own freshly generated encryption/signing keys (never reused across chats), and a bearer token hashed at rest that stops working the moment that participant leaves. `django.contrib.auth`'s `User` model still exists, but solely for Django's own admin/staff login — no end-user chat functionality touches it. See **[docs/ACCOUNTLESS_IDENTITY.md](docs/ACCOUNTLESS_IDENTITY.md)** for the full rationale, the red-team pass, and the honest tradeoffs (in particular: PIN/join brute-force throttling can no longer be keyed on an account, and is weaker as a result — especially without a Tor deployment's connection-level defenses in front of it).

## What's left for future work

Both structural blockers (#1, #2 above) are resolved, the crypto layer now covers forward secrecy, transcript tamper-evidence, TOFU key verification, and hardened client-side key storage in addition to E2E encryption, and messages/roster changes now push over a websocket instead of relying solely on polling. What remains open:

- **Service layer** (#6 above, issue #39): domain logic is still embedded in view methods.
- **Forward-secrecy ratchet/message keys still sit in plaintext `localStorage`** (found scoping #21/#42, tracked as issue #55): `docs/CLIENT_KEY_STORAGE.md` fixed the RSA private keys and bearer token specifically, but `chain_my_key_*`/`chain_recv_key_*`/`msgkey_*` have the same XSS-readable exposure and weren't in either issue's original scope.

## Network-layer anonymity (Tor) and its rate-limiting tradeoffs

The app anonymizes *content* (E2E encryption, no persistent identity) but originally said nothing about the *network* — hosting IP/location, and connecting users' real IPs were both fully exposed to normal HTTP hosting. See README.md's "Running as a Tor Hidden Service (Podman)" section for the deployment that closes this gap: Tor onion services have no exit node, so a `.onion` deployment hides the server's location *and* never exposes a client's real IP, without needing a VPN on either side.

This has a direct consequence for join/create rate-limiting: every connection through a Tor hidden service looks like it comes from the same loopback address, so any throttle keyed on client IP becomes a single shared bucket — one attacker's failures can lock out every legitimate user.

- **`JoinChatView`'s PIN-brute-force throttle is IP-keyed** (`failed_join_attempts` in `chat/views.py`). There's no account to key it on anymore — `CreateChatView`/`JoinChatView` are unauthenticated entry points by design (see `docs/ACCOUNTLESS_IDENTITY.md`). Under Tor this collapses to one shared bucket; the intended mitigation there is Tor's own protocol-level defense (`HiddenServicePoWDefensesEnabled` in `deploy/torrc`, a proof-of-work challenge Tor issues before a connection ever reaches Django), which is more robust against connection-flooding than an app-level CAPTCHA/PoW system would be. Under a plain non-Tor deployment, IP-keyed throttling is the only defense left, and it's genuinely weaker than the old per-account limiter this app used to have before accounts were removed — an accepted, disclosed tradeoff, not an oversight.
