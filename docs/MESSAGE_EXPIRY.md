# Disappearing Messages: Per-Message TTL, Read-Time Expiry, and Tombstoning

## The gap this closes

Message history was only ever deleted when a chat fully emptied (every participant had left — see `LeaveChatView`). There was no way to shrink the exposure window *within* an active, ongoing chat: if a device were seized or compromised mid-conversation, every message ever sent in that still-open chat was sitting there, fully decryptable. Issue #64.

## The design fork, and why it came out this way

The issue itself named an open question: TTL per-chat (simpler) or per-message, Signal-style (more flexible, more complexity)? And a second one it didn't name explicitly: does the countdown start at *send* time (simple, no new infrastructure) or *read* time (Signal's actual model, needs read tracking this app had no concept of at all)? Both were decided toward the harder option — per-message TTL, read-time expiry — deliberately, not by default.

That combination interacts with transcript tamper-evidence (`docs/FORWARD_SECRECY.md`'s hash chain, `chat/chain.py`) in a way worth being explicit about: every message's `prev_hash` is the hash of the message immediately before it. Naively deleting an expired row would mean every later message's `prev_hash` points at nothing — a false "tampered transcript" signal caused by expiry working as designed, not an attack.

With per-*chat* TTL, expiry is always oldest-first (every message shares one TTL, timestamps are monotonic), so surviving messages stay a contiguous suffix — only the single oldest-survivor link ever breaks, fixable with one per-chat cursor. Per-*message* TTL doesn't have that property: a short-TTL message can fully expire while older, longer-TTL messages around it remain, punching a hole anywhere in the transcript. That forces the heavier mechanism actually implemented here: **tombstoning**.

## The design: read receipts, a lazy sweep, and tombstoning

- **`Message.ttl_seconds`**: set once at send time, optional. Null (the default, and what every message before this feature had) means "never expires."
- **`MessageReadReceipt(message, participant, read_at)`**: created the first time a participant's authenticated `GET /chat/get-messages/` returns a given message to them — that's the only "read" signal this app has, since the server never sees plaintext and there's no client-side decrypt-success confirmation channel. A sender is recorded as having read their own message immediately at send time (they necessarily have, having just composed it).
- **`services.sweep_expired_messages(chat)`**: called lazily on every `get-messages` fetch — this app has no cron/scheduled job anywhere (see `chat/auth.py`'s `IDLE_TIMEOUT` reclaim and `LeaveChatView`'s empty-chat delete for the same "clean up on the next relevant request" pattern). For every message with a TTL that isn't yet tombstoned, it checks whether *every currently-active participant who was already in the chat when the message was sent* has a read receipt older than `ttl_seconds`. Two things about that "who's required" set:
  - **Left participants are excluded.** They no longer need to read anything.
  - **A participant who joined *after* the message was sent is excluded too, not just "not yet required."** Forward secrecy already means they can never derive that epoch's key and decrypt it at all (`docs/FORWARD_SECRECY.md`) — waiting on a read receipt from someone who mathematically cannot produce one would mean the message never expires.
  - If nobody who was present at send time is still active, the message is tombstoned immediately regardless of elapsed time — it's already permanently unreadable to everyone remaining, so there's nothing left to wait for.
- **Tombstoning** (`services._tombstone`): the message's `compute_chain_hash()` result is computed and persisted to `Message.tombstone_hash` *before* anything is touched. Then `encrypted_text`/`aes_nonce`/`aes_tag`/`mac` are set to null, its `MessageKey` (self-wrap) and all `MessageReadReceipt` rows are deleted — none of them have any remaining purpose once the content they refer to is gone. `chat/chain.py`'s `compute_chain_hash` checks `tombstone_hash` first and returns it directly when set, rather than recomputing from the now-null fields — this is the single piece of state that keeps the whole chain verifiable through an expiry, and it's a deliberate, narrow exception to that function's own "nothing here is ever persisted" design for an ordinary message.

## What this deliberately does *not* do: per-viewer content hiding

A message that's read-and-expired for Alice specifically, but not yet globally tombstoned (because Bob hasn't read it yet), is **not** given different content depending on who's asking. Serving Alice a redacted version while Bob still sees the real ciphertext would mean Alice's own chain-hash walk computes a different hash for that message than what's actually chained into by later messages — the same false-tamper problem tombstoning exists to avoid, just moved to be per-viewer instead of global.

Instead, "this vanished after I read it" is purely a **client-side, cosmetic** concern: once `chatbox.html` has rendered a message with a TTL, it starts its own local timer and fades/removes it from that browser's view — the same way Signal's own client enforces disappearing messages locally, not by the server serving different bytes to different recipients. The server's actual, enforced guarantee is coarser but real: content is irreversibly gone from storage once nobody legitimately needs it anymore. What a client does with its own already-received, already-decrypted copy before that point is a UI decision, not a security boundary — no messenger with local rendering can promise otherwise.

## What this catches

Once every legitimate reader's window has elapsed, the actual ciphertext, nonce, tag, and MAC are gone from the database — a DB compromise or forensic image taken after that point recovers nothing about that message's content, only that a message existed at that position in the transcript.

## What this explicitly does not give

- **No enforcement against a live, currently-rendering client.** Same caveat as `docs/CLIENT_KEY_STORAGE.md`'s non-extractable keys and `docs/DENIABLE_AUTH.md`'s MAC: this stops content from persisting in *storage* past its window, not from being screenshotted, copy-pasted, or otherwise captured by someone who legitimately saw it while it was live.
- **No guarantee within the read window.** A message with a very long TTL (or one whose recipient never opens the app until right before the deadline) can sit fully decryptable for that entire window, same as it always could.
- **The "read" signal is a fetch, not a confirmed decrypt.** If a client fetches a message but fails to decrypt it (corrupted state, a bug), the server still counts that as "read" — there's no channel for the server to know otherwise, since it never sees plaintext by design.

## What this is not

Same caveat as the project's other security docs: this narrows a real gap, it doesn't make Telepathy ready for a high-stakes use case like source protection on its own. See `ARCHITECTURE.md` for the full limitations list.
