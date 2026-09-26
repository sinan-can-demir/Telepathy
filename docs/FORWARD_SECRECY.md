# Forward Secrecy: What Changed and What Didn't

## The gap this closes

Before this change, every participant generated one RSA-OAEP/RSA-PSS "burner" keypair per chat (see `docs/ACCOUNTLESS_IDENTITY.md`), and that same keypair was reused to wrap *every* message's AES key for the chat's entire lifetime. The per-message AES key was already fresh each time — it's the *wrapping* key that was static. If that private key was ever extracted from `localStorage` (XSS, device compromise, disk forensics), the attacker could decrypt **every message ever sent in that chat**, past and future, not just messages from the point of compromise forward. That's the textbook absence of forward secrecy.

## The design: a per-sender symmetric ratchet

This is the same idea as Signal's "Sender Keys": each participant maintains their own one-way hash chain for messages *they* send, rather than every pair of participants running a full Diffie-Hellman ratchet (Signal's Double Ratchet). It's the right-sized piece of that design to hand-roll — see "What this explicitly does not give" below for the half that's deliberately left out.

- On joining a chat (or whenever the roster has changed since they last did this), a participant generates a random 32-byte seed and fans it out once to every other current participant, RSA-OAEP-wrapped per recipient (`ChainKey`/`ChainKeyWrap`, `IssueChainKeyView`) — reusing the same wrapping mechanism the old per-message scheme used, just for a seed instead of a message key.
- For message *i* from that sender: `message_key = HMAC-SHA256(chain_key, 0x01)`, then `chain_key = HMAC-SHA256(chain_key, 0x02)` — the message key is derived, the chain key advances, and the *old* chain key is discarded immediately. This mirrors Signal's own KDF chain construction (HMAC with a one-byte label) exactly.
- Only the *current* chain key ever persists, replacing what used to be a static keypair reused for the chat's whole lifetime. It's stored as a non-extractable HMAC `CryptoKey` object in IndexedDB, not raw bytes in `localStorage` — see "Where the keys actually live" below and `docs/CLIENT_KEY_STORAGE.md` (issue #55).
- **The actual gain**: stealing `chain_key` at some point *T* only yields message keys from *T* forward. HMAC is one-way — there is no computation that recovers `chain_key` at *T-1* from `chain_key` at *T* — so messages sent before the compromise stay unrecoverable from that stolen state. That's forward secrecy, and it's a real, meaningful improvement over the previous total-history exposure.
- **Re-keying on membership change**: whenever a participant joins or leaves, every sender's next send issues a fresh epoch (`ChainKey.epoch` increments) before deriving that message's key. A new joiner is only ever handed a wrapped seed for the epoch issued after they joined, so they can't walk the one-way chain backward to derive keys for messages sent before they arrived — the one-way property already prevents that even if they wanted to.

## What the server sees (and doesn't)

No per-message key is stored for anyone (since #99). The sender keeps its own copy of each message key in this browser's IndexedDB (`mykey_*`, by chain position) to redisplay its sent history; the server used to keep an RSA-OAEP self-wrapped copy instead (`MessageKey`, now removed).

**Correction.** An earlier version of this section said that server-side self-wrap "does not weaken" forward secrecy. It did. The wrap was made to the sender's long-lived RSA key and kept on the server for the chat's lifetime, so anyone who later got a copy of the database *and* that RSA key (the adversary forward secrecy exists for) could decrypt the sender's entire sent history, however far the ratchet had moved. Threat-model finding T-05 / issue #99.

Other recipients get **no per-message wrapped key at all**. They derive the same message key locally by advancing their own cached copy of the sender's chain — the only thing ever transmitted for them is the one-time wrapped seed at chain-issuance time (`GetChainKeysView`). This is also a genuine efficiency win: an N-person group chat no longer needs N RSA-OAEP wrap operations per message, just one HMAC step per recipient.

## What the server keeps, and the limits that remain (issue #99)

The ratchet only protects the past if nothing *else* can re-derive it. Two server-side copies used to be able to:

1. **The wrapped chain seed** (`ChainKeyWrap`) was kept for the chat's whole life. With the recipient's RSA key, it re-derives every key of that chain from index 0.
2. **The sender's self-wrap** (`MessageKey`), described above.

Now the receiver acknowledges a seed (`POST /chat/ack-chain-key/`) once a message under it has decrypted and the seed is stored locally, and the server deletes that wrap and any older ones for that sender. The ack comes only after a successful decrypt (#94): a seed that hasn't been proven good must stay fetchable, or a single message the server lies about would lose the whole epoch. The self-wrap is gone entirely.

What still holds, stated precisely:

- **A copy taken before the ack still works.** A wrapped seed exists on the server from issuance until the recipient's first successful decrypt under it. An operator who logs it at fetch time, or a database copy taken in that window, plus the recipient's RSA key, still yields that epoch from index 0 up to the next re-key. This defends against a *later* database copy, not against a hostile server (that is T-04's territory).
- **A failed ack leaves the wrap.** The ack is best effort; if it's lost, the wrap stays until the chat is deleted (on leave, or by the idle reaper after 30 minutes, #97).
- **The device holds history by design.** `msgkey_*` and `mykey_*` hold the key of every message this browser has shown, so anyone with this browser's storage can read everything it can display. That is the price of redisplaying history after a reload, as in any messenger that keeps history.
- **The RSA key lives until you leave.** Non-extractable means JavaScript can't export it, not that it can't be used by any script in the page or recovered from the browser profile on disk.
- **Losing local storage loses history**, now including your own sent messages, which show as "could not be decrypted" on another device or after clearing site data. Received messages already worked this way.

## The reload problem, and how it's actually solved

A forward-secret ratchet that's genuinely discarding old keys creates an obvious tension with "reload the page and still see your message history," which this app has always supported by re-fetching ciphertext from the server and redecrypting on every load. The fix: the first time a client successfully derives a message's key via the ratchet, it caches *that specific derived key* locally, indexed by the message's own ID — not the ratchet position. A reload replays cached per-message keys for everything already seen (no ratchet involvement, no re-advancement) and only touches the live ratchet state for genuinely new messages. The ratchet's forward-secrecy property is about what's recoverable from a *stolen* snapshot of current state, not about what a legitimate, continuously-used client can still display to the person who's been reading it the whole time.

## Where the keys actually live (issue #55)

The sending chain key, each per-sender receiving chain key, and the per-message key cache (`chain_my_key_*`, `chain_recv_key_*`, `msgkey_*`, `skipkey_*` in `chatbox.html`) are stored as non-extractable `CryptoKey` objects in the same IndexedDB store `docs/CLIENT_KEY_STORAGE.md` set up for the RSA keys and bearer token, not as raw base64 bytes in `localStorage`. `ratchetStep` takes a chain key `CryptoKey` and signs with it directly (`crypto.subtle.sign` accepts a `CryptoKey`, no export round-trip needed); an HMAC's *output* is unavoidably a raw buffer, so it's re-imported into a fresh non-extractable key immediately, rather than ever touching storage as raw bytes.

An HMAC's output is always a raw buffer, so on both paths the freshly derived message key exists as raw bytes only long enough to be imported as a non-extractable `CryptoKey`; it is never persisted in that form. (Before #99 the sending side also had to keep the raw bytes around to RSA-wrap them for its self-copy; that's gone.)

## Missing messages: chain index and skipped keys (issue #90)

Advancing "once per message seen" only works if every message reaches every receiver. Once the server can lose messages (a Redis restart, an aged-out relay entry -- see `docs/EPHEMERAL_RELAY.md`), losing message *k* would leave every later key from that sender one step off, permanently, until a re-key.

So each message carries `chain_index`: its position within the sender's current epoch (0 for the epoch's first message). A receiver keeps `{chainKey, index}` per sender (one IndexedDB record, so the key and its position can't be persisted out of step) and, on a message at index *n*, ratchets forward from `index` to *n*. The keys for the positions it stepped over are kept as `skipkey_*` entries, because the chain is one-way and a key not kept can never be recovered; if the missing message turns up late it is decrypted with its kept key, once. A message whose index is already behind the receiver and has no kept key is refused as a replay. A single message can make a receiver skip at most `MAX_SKIP` (100) positions, so a hostile index can't pin the tab in a huge HMAC loop.

`chain_index` is not separately MAC'd: it selects which key decrypts the message, so a server that lies about it makes AES-GCM decryption fail before the MAC is reached. Because that failure *is* the attack, nothing is written until the decrypt succeeds (#94): `deriveReceivedKeys` returns a `commit()` holding every write (skipped keys, the message's own key, the advanced chain, a re-seeded epoch, the seed ack), and the message is shown as undecryptable and retried if the decrypt fails. Within `commit()` the message's own key is cached *before* the advanced chain, so an interruption between the two self-heals on the next message (the gap is re-derived as skipped keys) instead of desyncing.

This does not recover the *content* of a lost message -- that is gone -- it only stops one loss from taking the rest of the conversation with it.

## What this explicitly does not give

This is not post-compromise security (Signal calls this "self-healing"). If an attacker obtains a participant's *current* chain key, they can derive every future message key from that sender too, until the next membership-change re-key — the ratchet only runs forward from wherever the attacker caught it. Real self-healing needs a Diffie-Hellman ratchet mixed in periodically (the other half of Signal's Double Ratchet), which requires fresh ephemeral key exchanges, not just a one-way hash chain.

That's deliberately out of scope here: hand-rolling a correct, secure multi-party DH ratchet is a genuine research-grade correctness/security risk for a solo/learning project. If Signal-equivalent post-compromise security is ever wanted, the right move is adopting a vetted library rather than extending this hand-rolled protocol further.

## What this is not

Same caveat as `docs/ACCOUNTLESS_IDENTITY.md`: this narrows a real gap, it doesn't make Telepathy ready for a high-stakes use case like source protection on its own. Key verification (TOFU/safety numbers) is now in place — see `docs/KEY_VERIFICATION.md`. Metadata minimization remains open. See `ARCHITECTURE.md` for the full limitations list.
