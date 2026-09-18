# Security Audit: Adversarial Review of the Crypto/Auth Core

## Why this exists

Every prior security doc in this repo (`ACCOUNTLESS_IDENTITY.md`, `FORWARD_SECRECY.md`, `KEY_VERIFICATION.md`, `CLIENT_KEY_STORAGE.md`) was written alongside the feature it describes, verified by the same means the feature itself was: unit tests passing, a live two-participant smoke test working. That's real verification of *correctness under normal use* -- it is not the same thing as verification against an adversarial model, and none of those docs claimed otherwise.

This doc is the result of going back over the hash chain (`chat/chain.py`), the sender-ratchet forward-secrecy design, RSA-OAEP/RSA-PSS usage, client-side key storage, and auth/session handling specifically looking for code that behaves correctly on the happy path but fails under concurrency, a hostile server, or a client that doesn't play along with the JS's own invariants. Six concrete, fixable bugs came out of it, filed as issues (#67-#72). Three more things were checked and are called out below as either ruled out or not worth a tracked issue on their own.

## Findings filed as issues

### Forward-secrecy ratchet desync under concurrency (#67, #68)

The sender-chain ratchet (`docs/FORWARD_SECRECY.md`) is a one-way HMAC chain: each message advances the chain exactly once, in strict order, on both the sending and receiving side. That "exactly once, in strict order" invariant is the load-bearing assumption for the whole design, and it turns out not to hold under two realistic conditions:

- **#67** -- the sending side commits its ratchet advance to `localStorage` *before* knowing whether the server accepted the send. A `409` (two participants sending at once -- an entirely normal occurrence, not an attack) leaves the local chain state permanently one step ahead of what any receiver will derive, with no rollback. Every subsequent message from that sender silently fails to decrypt for everyone else.
- **#68** -- the receiving side is vulnerable to the same desync via a different path: the app runs a WebSocket push and a 15-second poll concurrently by design, and two overlapping `fetchNewMessages()` calls can race the same sender's cached chain state across an `await` boundary, causing two different messages to derive the same key and the chain to only advance once for both.

Neither is reachable by a single-user test. Both are reachable by perfectly ordinary two-person concurrent use, which is exactly the condition this app exists for.

### Server doesn't enforce the ratchet's own security invariant (#69)

Re-keying on roster change exists specifically so a participant who leaves a chat loses the ability to decrypt messages sent after they left. `SendMessageView` only checks that a submitted `sender_chain_epoch` *exists*, never that it's the sender's *current* one -- so nothing server-side stops a sender (buggy client, stale cache, or a client bypassing the JS entirely) from continuing to use an epoch a since-departed participant already holds, silently defeating the re-keying guarantee for the rest of the chat.

### Tamper detection without enforcement (#70)

The client-side chain-verification walk (`updateChainState`) correctly detects a dropped, reordered, or replayed message and flips a warning banner -- but explicitly continues building and sending new messages on top of the server's own (unverified) reported tip regardless of whether verification failed. Detection exists; nothing consumes it. A malicious server can drop a message and get nothing worse than a banner most users won't notice, with no cryptographic signal of the break ever reaching the other participant.

### Leave-on-tab-close is silently non-functional (#71)

`beforeunload`'s `sendBeacon` call to `/chat/leave-chat/` cannot carry the `Authorization` header the endpoint requires, so it is rejected by the server on every single tab close -- not just missing a nice-to-have, actually failing every time, silently, with no cleanup of local ratchet/key state as a fallback either. Combined with #55 (ratchet keys still plaintext in `localStorage`), this means the plaintext key material and the still-valid session token both outlive the tab indefinitely on the ordinary "close the browser" exit path, not just the already-known "XSS could read localStorage" exposure.

### Key intake takes presence for correctness (#72)

`public_key`/`signing_public_key` are accepted with only a truthiness check -- no format, type, or size validation -- despite every client-side `importKey` call assuming a specific, well-formed 2048-bit RSA SPKI PEM. Low severity (the server can't validate honesty of a key in an E2EE design regardless) but a clean example of validation that satisfies "the field is present" without checking "the field is usable."

## Checked and ruled out (not filed)

- **Hash-chain delimiter injection** (`chat/chain.py`'s `"|".join(...)` with no escaping): every variable-length field going into it is base64, whose alphabet never contains `|`, so no two distinct messages can collide via a shifted delimiter today. Fragile if a non-base64 field is ever added to that tuple, but not currently exploitable -- not worth an issue on its own, just a note for whoever touches `compute_chain_hash` next.
- **Token comparison timing** (`chat/auth.py`): the lookup compares a SHA-256 hash via a DB query, not a Python `==`. Not a meaningful timing side-channel in practice (you'd need to time a preimage attack over a network round-trip against an indexed hash lookup), so not tracked separately.
- **`chat_id` absent from the hash chain input**: not independently exploitable today because `sender_id` is 1:1 bound to one `Chat` via FK and `(chat, seq)` is DB-unique, so cross-chat splicing has no room to work with. Binding `chat_id` explicitly would remove the reliance on that indirect argument at zero cost, but there's no live attack here to justify a standalone issue.

## What was already tracked before this pass

Two things this audit turned up were already filed: the WebSocket bearer token traveling via URL query string (#57) and the general plaintext-ratchet-keys-in-localStorage exposure (#55). Both are referenced above rather than re-filed. #60 (no post-compromise security) is a related but distinct question -- this audit's #69 is about the *existing* re-key mechanism not being enforced, not about whether one-way hash-chain re-keying is enough in principle.
