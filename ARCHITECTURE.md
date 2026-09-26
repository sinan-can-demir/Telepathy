# Architecture Notes & Known Limitations

This document captures the results of an architecture review of the current codebase — not a security audit (see the closed/open security issues in the tracker for that), but an assessment of whether the foundation can support future features without a rewrite.

## Verdict

The crypto/API layer is solid: end-to-end encryption, transcript tamper-evidence (hash-chained messages), forward secrecy (a per-sender HMAC ratchet), deniable per-message authentication (a ratchet-derived MAC, not a signature — see `docs/DENIABLE_AUTH.md`), TOFU key verification, and hardened client-side key storage (non-extractable `CryptoKey`s in IndexedDB) are all in place — see `docs/ACCOUNTLESS_IDENTITY.md`, `docs/FORWARD_SECRECY.md`, `docs/KEY_VERIFICATION.md`, and `docs/CLIENT_KEY_STORAGE.md`. The structural data-model problems that used to block group chat and long-term PIN availability are both resolved, the transport layer pushes new messages/roster changes over a websocket instead of relying solely on polling, and domain logic now lives in `chat/services.py` rather than directly in view methods. All six items originally listed below are resolved.

## Known limitations, ranked by how much they block future work

### 1. ~~`Message` has no foreign key to `Chat`~~ — Resolved

`Message.chat` is a real foreign key (`chat/models.py`), and `GetMessagesView`/`SendMessageView` query through `chat.messages` rather than inferring conversation identity from a `(sender, receiver)` pair. This was the prerequisite for group chat, which now exists (`ChatParticipant`, `docs/GROUP_CHATS_PLAN.md`).

### 2. ~~The 4-digit PIN space (10,000 values) is never recycled~~ — Resolved

`LeaveChatView` now hard-deletes the `Chat` row once every participant has left (cascading to its `ChatParticipant`/`Message`/`ChainKey` rows), instead of soft-flagging it with `is_active=False` forever. `Chat.pin`'s uniqueness constraint only applies to chats that still exist, so an ended chat's PIN is immediately available for a new chat to reuse (#35).

### 3. ~~`active_chats` in-process dict is dead code today, a landmine tomorrow~~ — Resolved

Removed entirely as part of the Phase 1 group-chat schema migration. If presence/online-status is wanted later, it belongs in Postgres (`ChatParticipant.left_at`, or the fact that a `Chat` row exists at all now that ended chats are hard-deleted) or Redis, not a per-process dict.

### 4. ~~Polling transport is a reasonable MVP choice, but `channels` is a half-installed illusion~~ — Resolved

`pc/asgi.py` now routes through a real `ProtocolTypeRouter`, `chat/consumers.py` and `chat/routing.py` exist, and `CHANNEL_LAYERS` uses a Redis backend (`channels_redis`). `SendMessageView`/`JoinChatView`/`LeaveChatView` push a lightweight signal (`chat/realtime.py`'s `notify_chat`) over the chat's websocket group on every new message or roster change, and the client (`chatbox.html`) immediately re-runs its existing HTTP fetch on receiving one instead of waiting for the next poll tick — HTTP polling is kept, just slowed to a 15s fallback for reconnect gaps, per issue #37's own "additive, don't remove the REST endpoints" direction. Production now runs `daphne` (an ASGI server) instead of `gunicorn` (WSGI-only, can't serve websocket upgrades at all), and `compose.yaml` gained a `redis` service.

One dependency note worth keeping in mind going forward: `channels_redis==4.2.1` has no upper bound on its own `redis` dependency, so a plain `pip install` pulls `redis>=8`, which has real async timeout/connection-pool incompatibilities with it (reproduced locally — the channel layer's background listener crashed with a spurious `redis.exceptions.TimeoutError` under load). `requirements.txt` pins `redis==5.0.8` explicitly to avoid this; don't let that pin drift without re-testing against whatever `channels_redis` version is current at the time.

### 5. ~~Chat identity is tracked in two places that can disagree~~ — Resolved

The server used to also stash `chat_id` in the Django session (read by the page-rendering `chatbox` view), duplicating what the frontend JS already tracked in `localStorage`. The `chatbox` view no longer reads or writes any session state — `localStorage` (used by every fetch-based API call) is the sole source of truth for "what chat is this browser currently in."

### 6. ~~Fat views, no service layer~~ — Resolved

Chat-pairing/leave/messaging/chain-key rules now live in `chat/services.py` as plain functions taking/returning model values and raising typed exceptions (`ChatNotFound`, `ChatFull`, `NotAParticipant`, `StaleTranscript`, `StaleChainEpoch`, `UnknownChainEpoch`, `RosterMismatch`, ...) for domain-rule violations — never a DRF `Response`. Every `APIView` method in `chat/views.py` is now a thin adapter: parse `request.data`, call into `services`, catch its exceptions, map each to the right HTTP status/body. `ChatServicesUnitTests` in `chat/tests.py` exercises these directly against the test database, with no `APIClient`/HTTP round trip at all (issue #39).

One deliberate, non-behavior-preserving side effect: a handful of endpoints (`send-message`, `issue-chain-key`, `get-chain-keys`, `get-chat-participants`, `get-messages`) previously returned DRF's default `{"detail": "Not found."}` body for a missing chat, via `get_object_or_404`. They now return `{"message": "Chat not found."}`, matching the convention every other error response in this file already used — status codes are unchanged, and no test asserted the old body.

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

All six numbered items above are resolved, including the service layer (#6, issue #39) and the forward-secrecy ratchet/message keys that used to sit in plaintext `localStorage` (issue #55, `docs/CLIENT_KEY_STORAGE.md`/`docs/FORWARD_SECRECY.md`). Remaining open work (a service-layer refactor pass, deployment/feature hardening, and larger strategic bets like post-compromise security or a P2P redesign) is tracked in the issue tracker rather than duplicated here — see `gh issue list`.

## Network-layer anonymity (Tor) and its rate-limiting tradeoffs

The app anonymizes *content* (E2E encryption, no persistent identity) but originally said nothing about the *network* — hosting IP/location, and connecting users' real IPs were both fully exposed to normal HTTP hosting. See README.md's "Running as a Tor Hidden Service (Podman)" section for the deployment that closes this gap: Tor onion services have no exit node, so a `.onion` deployment hides the server's location *and* never exposes a client's real IP, without needing a VPN on either side.

This has a direct consequence for join/create rate-limiting: every connection through a Tor hidden service looks like it comes from the same loopback address, so any throttle keyed on client IP becomes a single shared bucket — one attacker's failures can lock out every legitimate user.

- **Joining no longer depends on the client's address at all.** The IP-keyed limiter on the old 4-digit PIN was bypassable through `X-Forwarded-For` and, under Tor, one shared bucket that let one client lock out everyone (#95). It was replaced by single-use invites (#101, `docs/DESIGN_JOIN_SECRET.md`): a 30-bit code stored as a keyed HMAC, with every wrong code charged to *that invite* (three and it's burned), so nothing keys on an address. What's left address-shaped is load: chat creation is still unthrottled, and Tor's `HiddenServicePoWDefensesEnabled` (`deploy/torrc`) plus Tor Client Authorization (#62) are the defenses against floods.

## Accepted limitations

Four known gaps were deliberately decided against fixing, rather than left as forgotten open work. Both are recorded here so the project doesn't overstate what it guarantees.

- **The client code is trusted on every page load (issue #42).** The browser runs whatever JavaScript the server serves, so a compromised or malicious server could ship modified crypto code and defeat the end-to-end guarantees for anyone who loads it. TOFU key pinning, the transcript hash chain, and the deniable MAC catch a server that tampers with *data*; none of them can catch a server that tampers with the *code doing the checking*. Packaging the client natively (Tauri) would pin the code, but it would also need a bundled Tor client to keep the `.onion` deployment usable, give up the open-a-URL-and-go property, and add per-OS builds, code signing, and an update channel. That cost wasn't judged worth it for a solo learning project; revisit if this ever has real users. Until then, treat the server operator as able to see anything a user's browser can see.
- **Old test private keys remain in git history (issue #2).** Early commits contain RSA private keys (`*_private_key.pem`) from a since-removed account-based test keygen. They protect nothing current: keys are now generated per chat in the browser, non-extractable, and never reused. A history rewrite was decided against because it would change every commit SHA and still couldn't remove copies already held by the upstream repo, existing clones/forks, or GitHub's cached refs. gitleaks runs in CI (`.github/workflows/secret-scan.yml`) to keep new ones out.
- **Message timing is observable on the wire (issue #63).** To anyone who can watch a Tor client's traffic, a real message is visible as an event: the sender makes an HTTP `POST /chat/send-message/` at send time, and every receiver gets a small websocket signal followed immediately by a `GET /chat/get-messages/` that returns the *whole* transcript, so the response grows with each real message. The 15-second fallback poll is constant background noise, but its response size still changes whenever the transcript does (a new message, or an expiry tombstone replacing one), and a roster change shifts it too. This matters only against a *global passive adversary* correlating traffic timing; it does nothing about the more common threats (a compromised server, XSS, device seizure). The issue's proposed fix, dummy frames on the websocket, would not close it: the websocket only carries server-to-client signals, so it can't mask the sender's POST or the receivers' refetch, and would add bandwidth without an anonymity gain. A real fix is a constant-rate mode (fixed-interval real-or-dummy send slots, delta or fixed-size fetches, server-side handling of dummies without disturbing the hash chain or ratchet), which is a redesign of the send path with real latency and battery cost. Not judged worth it for this project; if ever pursued, make it opt-in and design it first. This analysis is from reading the code, not from measured traffic captures.
- **No post-compromise security (issue #60).** The forward-secrecy ratchet only runs forward: an attacker who obtains a participant's current chain key can derive that sender's future message keys until the next membership-change re-key, with no way to self-heal. Real healing needs a DH/KEM-style ratchet; a periodic re-key wrapped to the static RSA burner keys would not heal a device compromise. For groups the only vetted route is MLS (RFC 9420), but the browser implementations looked at are young (`ts-mls` states it has not been formally audited), MLS sender signatures conflict with the deniable-MAC decision in #61, and it would replace most of the client crypto layer and add a build step. Not judged worth it for a solo learning project with no deployed users. Full analysis, options, and what "taking it seriously" would change in `docs/DESIGN_POST_COMPROMISE_SECURITY.md`.
