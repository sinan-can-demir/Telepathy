# Architecture Notes & Known Limitations

This document captures the results of an architecture review of the current codebase — not a security audit (see the closed/open security issues in the tracker for that), but an assessment of whether the foundation can support future features without a rewrite.

## Verdict

The crypto/API layer is solid and reusable. The data model and transport layer encode assumptions — "exactly one 1:1 chat per PIN, forever, from a 10,000-slot keyspace," "polling is fine forever" — that will actively resist most plausible next features. The two biggest problems are not obvious from reading the code casually; they require tracing how `Message`, `Chat`, and the PIN space actually relate.

## Known limitations, ranked by how much they block future work

### 1. `Message` has no foreign key to `Chat`

Chat identity is inferred from `(sender, receiver)` user pairs (`chat/models.py`), not a `chat_id` on the message itself. `GetMessagesView` and `SendMessageView` (`chat/views.py`) both look up messages via `Q(sender=me) & Q(receiver=partner) | ...`, never via a chat reference.

Consequences:
- Two users can never have more than one *logical* conversation the server can distinguish. `LeaveChatView` works around this by hard-deleting all messages between the pair on leave — message persistence is coupled to session lifecycle instead of being treated as durable data.
- Group chats, multi-device support, or "same two people, two separate topics" are impossible without adding a `chat` FK to `Message` and rewriting the query layer. This is a schema migration, not an additive change.

**Direction**: add `Message.chat = ForeignKey(Chat, related_name="messages")`, backfill by matching existing `(sender, receiver)` pairs to their `Chat`, then switch queries to `chat.messages.filter(...)`. This is also a prerequisite for group chat, which additionally needs a `ChatParticipant` join model replacing the fixed `user1`/`user2` slots.

### 2. The 4-digit PIN space (10,000 values) is never recycled

`CreateChatView` generates PINs via `random.randint(0, 9999)` and rejects on collision, but `Chat.pin` is `unique=True` forever — `LeaveChatView` only sets `is_active=False`, it never deletes the row. Every chat ever created permanently retires one of only 10,000 possible PINs. This is a hard ceiling on **total lifetime chats**, not concurrent ones — once the space fills up, PIN generation degrades to scanning an increasingly full space and eventually fails outright.

**Direction**: decouple the PIN from chat identity. A `Chat` should have its own permanent surrogate key (already does, via Django's auto `id`); the 4-digit PIN becomes a separate, short-TTL, reusable pairing code that's deleted once both parties join or after expiry. Ended chats get hard-deleted or archived instead of just flagged, freeing the code space.

### 3. `active_chats` in-process dict is dead code today, a landmine tomorrow

Written to in `CreateChatView`, `JoinChatView`, and `LeaveChatView`, but never read anywhere (confirmed by full-project grep). Harmless right now, but under multiple worker processes or pods, each process has its own empty dict — the moment someone wires a read to it (e.g. for a "who's online" feature), it silently breaks in production while working fine in single-process dev.

**Direction**: delete it outright. If presence/online-status is wanted later, it belongs in Postgres (there's already `Chat.is_active`) or Redis, not a per-process dict.

### 4. Polling transport is a reasonable MVP choice, but `channels` is a half-installed illusion

The frontend polls `GetMessagesView` every ~2 seconds. `channels==4.2.0` is a listed dependency with `ASGI_APPLICATION` set in `pc/settings.py`, but `pc/asgi.py` only calls `get_asgi_application()` — no `ProtocolTypeRouter`, and no `consumers.py`/`routing.py` exist anywhere in the repo. The dependency implies infrastructure that was never built, which is worse than not listing it at all.

This doesn't block shipping today, but it's a foundational blocker for anything that needs to feel real-time: typing indicators, read receipts, presence. Server load also scales linearly with active chats × polling frequency regardless of actual message volume, and there's a hard ~2s latency floor.

**Direction**: since `channels` and `channels_redis` are already dependencies, stand up a real `consumers.py` + `routing.py` with a Redis channel layer. Keep HTTP polling as the initial-load/fallback path; move only "new message" push and future presence/typing signals onto the websocket. This is additive — it doesn't require removing the REST endpoints, since persistence stays in the existing request path and the websocket layer only fans out notifications.

### 5. Chat identity is tracked in two places that can disagree

The server stores `chat_id` in the Django session (used by the page-rendering `chatbox` view), while the frontend JS independently stores it in `localStorage` (used by all fetch-based API calls). These are two sources of truth for "what chat is this browser currently in," updated independently. Minor today, but any future multi-tab or multi-device support will need to reconcile them.

### 6. Fat views, no service layer

Chat-pairing logic (slot assignment, in-memory mirroring, message cleanup on leave) lives directly inside `APIView.post`/`get` methods in `chat/views.py`, mixing HTTP status-code decisions with domain rules. There's no `chat/services.py` or model-level methods (e.g. `Chat.add_participant(user)`) to unit-test independent of DRF request/response plumbing — every test of pairing/leave/visibility logic currently has to go through a full `APIClient` HTTP round trip.

**Direction**: extract pairing/leave/messaging rules into plain functions or model methods that views call into. Lets core chat rules be tested in milliseconds without spinning up the request/response cycle, and makes it easier to compose new behavior (e.g. "notify partner on join") without re-editing the view.

## What's already solid and doesn't need to change

- **Serializers** (`chat/serializers.py`) are clean, idiomatic DRF `ModelSerializer`s — no manual dict construction creeping into view logic.
- **Indexing** on `Message` (`sender`, `receiver`, `timestamp`, plus a composite `(receiver, -timestamp)` index) is well-matched to the actual polling query pattern.
- **Client/server crypto boundary** is genuinely clean: the server only ever touches ciphertext and PEM blobs, never plaintext or private key material. This API surface is pure JSON + token auth and could be reused as-is by a future mobile app or SPA.
- **UUID primary key on `Message`** avoids sequential-ID enumeration and is a reasonable choice if message data is ever synced or sharded.
- The split between page-rendering views and JSON API views is at least consistently named, even though their state overlaps awkwardly (see #5 above).
- The inline-script frontend approach isn't a crisis at the current scope — no framework is needed for a single-page polling chat — but it's already showing strain and will need extraction into modules before another screen's worth of UI logic is added.

## Relationship to feature planning

Limitations #1 and #2 should shape any near-term feature scoping rather than follow it — a `Message → Chat` foreign key is a prerequisite for group chats, message search scoped to a conversation, or any multi-conversation feature, and the PIN-recycling fix determines whether the app can survive past ~10,000 total chats. Worth deciding on these before committing to a feature design that assumes the current schema.

See [docs/GROUP_CHATS_PLAN.md](docs/GROUP_CHATS_PLAN.md) for a concrete plan that resolves limitation #1 as groundwork before building group chat support on top of it.

## Network-layer anonymity (Tor) and its rate-limiting tradeoffs

The app anonymizes *content* (E2E encryption, no persistent identity) but originally said nothing about the *network* — hosting IP/location, and connecting users' real IPs were both fully exposed to normal HTTP hosting. See README.md's "Running as a Tor Hidden Service (Podman)" section for the deployment that closes this gap: Tor onion services have no exit node, so a `.onion` deployment hides the server's location *and* never exposes a client's real IP, without needing a VPN on either side.

This has one direct consequence for the rate-limiting added earlier (#20, #9/#10): every connection through a Tor hidden service looks like it comes from the same loopback address, so any throttle keyed on client IP becomes a single shared bucket — one attacker's failures can lock out every legitimate user.

- **`LoginView`'s throttle was re-keyed from client IP to the targeted username** (`failed_login_attempts` in `chat/views.py`). This is a strictly better mitigation independent of Tor — it throttles brute-forcing of a specific account, the actual attack, rather than a source address that's either collapsed by Tor or trivially rotated by a clearnet attacker anyway.
- **`RegisterUserView`'s throttle was deliberately left IP-keyed.** There's no account yet to key registration attempts on, so under Tor it becomes a no-op single bucket. This is an accepted tradeoff, not an oversight: Tor onion services have a protocol-level defense for exactly this (`HiddenServicePoWDefensesEnabled` in `deploy/torrc`, a proof-of-work challenge Tor issues before a connection ever reaches Django), which is a more robust fix for connection-flooding than an app-level CAPTCHA/PoW system would be. If registration abuse becomes a real problem in practice, revisit this rather than assuming the current IP-keyed check is doing anything useful behind Tor.
