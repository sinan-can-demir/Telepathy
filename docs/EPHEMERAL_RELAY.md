# Ephemeral relay-only mode (issue #90)

**Status: design agreed, implementation staged across the PRs listed at the end.**
Starting point: `docs/DESIGN_P2P.md` (why WebRTC was rejected). This doc records
what the code actually required and the decisions made.

## Goal

The server stops *keeping* message data. Ciphertext lives in Redis only, until
every active participant has acknowledged it or a TTL lapses, and never touches
Postgres. Clients keep their own transcript. This shrinks what a server
compromise *after the fact* yields; it does not blind a live server (it still
sees who talks, when, and how much) and a malicious server can still drop or
delay messages.

## Decisions

| Question | Decision |
|---|---|
| TTL for undelivered ciphertext | **7 days**, per message, in Redis. Deleted sooner once every active participant has acked it. |
| What counts as delivered | **Explicit ack** (`POST /chat/ack/<chat_id>/`), sent only after the message is durably in the client's IndexedDB. Fetch alone is not delivery, so a crash or dropped response can't lose a message. |
| Surviving a missing message | **Per-chain counter + skip-ahead**: each message carries its index within the sender's epoch; receivers ratchet forward N steps and cache the skipped keys. |
| Local transcript format | **Messages as served (still encrypted)** in IndexedDB. Chain verification and the render/decrypt path are unchanged; at-rest security matches the existing key store (#55/#56). |

## What the code required (beyond the sketch in DESIGN_P2P.md)

1. **The ratchet can't survive a lost message today.** `deriveReceivedKeys`
   advances the sender's chain exactly once per message it sees, and messages
   carry only `sender_chain_epoch`, not a position within the epoch. Losing
   message *k* makes every later key from that sender wrong until a new epoch.
   Today the server keeps everything so this can't happen; with a TTL or a Redis
   restart it can. Hence the counter (`chain_index`), bound into the sender's MAC
   so the server can't rewrite it undetected.
2. **The server needs a durable chain tip.** `send_message` derives
   `expected_prev_hash` from the last stored `Message` for the 409 stale-transcript
   check. With messages gone from Postgres, `Chat` gains `tip_seq` and
   `tip_hash` (the chain hash of the last message), updated under the existing
   row lock. That is chain metadata only, no content.
3. **The client keeps no transcript today.** It refetches everything and
   re-decrypts from cached keys. It now needs a local message store, and
   `updateChainState` must verify against it instead of only the served list.
4. **A dropped message and a tampered transcript look identical.** A gap from a
   Redis restart is indistinguishable from a malicious server dropping a message.
   The banner wording changes from "tampered" to "messages missing or tampered".
   After a gap the chain re-anchors at the next message present.

## Defaults taken (flag if you disagree)

- **Late joiners** verify the chain from the tip supplied at join time, not from
  seq 0. They can't decrypt earlier messages anyway (forward secrecy), so nothing
  readable is lost.
- **Disappearing messages (#64) become client-enforced.** The server deletes
  after delivery regardless, so a per-message TTL only governs the local copy.
  Previously the server tombstoned its copy; a server-side wipe can never reach a
  client's local store, so the enforcement boundary genuinely moves.
- **Leavers** stop being waited on: a participant who has left is no longer
  required to ack.
- **Redis restart** loses undelivered messages; the counter + skip-ahead means
  later messages still decrypt.
- **Redis persistence stays off** (already true in `compose.yaml`).

## What this does not fix

Live metadata (who, when, how much), a malicious server dropping or delaying
messages, timing correlation (see `ARCHITECTURE.md`, Accepted limitations, #63).
New device or cleared browser storage now loses history, a deliberate behavior
change consistent with "Ephemeral".

## Staged implementation

1. **Chain counter + skip-ahead** (crypto path; also fixes desync on any gap).
2. **Server relay**: `Chat.tip_*`, Redis message store with TTL, ack endpoint,
   delete-on-ack, sweep/receipt rework.
3. **Client local transcript**: IndexedDB store, ack after save, gap-aware chain
   verification, banner wording.
