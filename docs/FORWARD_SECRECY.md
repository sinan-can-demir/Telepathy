# Forward Secrecy: What Changed and What Didn't

## The gap this closes

Before this change, every participant generated one RSA-OAEP/RSA-PSS "burner" keypair per chat (see `docs/ACCOUNTLESS_IDENTITY.md`), and that same keypair was reused to wrap *every* message's AES key for the chat's entire lifetime. The per-message AES key was already fresh each time — it's the *wrapping* key that was static. If that private key was ever extracted from `localStorage` (XSS, device compromise, disk forensics), the attacker could decrypt **every message ever sent in that chat**, past and future, not just messages from the point of compromise forward. That's the textbook absence of forward secrecy.

## The design: a per-sender symmetric ratchet

This is the same idea as Signal's "Sender Keys": each participant maintains their own one-way hash chain for messages *they* send, rather than every pair of participants running a full Diffie-Hellman ratchet (Signal's Double Ratchet). It's the right-sized piece of that design to hand-roll — see "What this explicitly does not give" below for the half that's deliberately left out.

- On joining a chat (or whenever the roster has changed since they last did this), a participant generates a random 32-byte seed and fans it out once to every other current participant, RSA-OAEP-wrapped per recipient (`ChainKey`/`ChainKeyWrap`, `IssueChainKeyView`) — reusing the same wrapping mechanism the old per-message scheme used, just for a seed instead of a message key.
- For message *i* from that sender: `message_key = HMAC-SHA256(chain_key, 0x01)`, then `chain_key = HMAC-SHA256(chain_key, 0x02)` — the message key is derived, the chain key advances, and the *old* chain key is discarded immediately. This mirrors Signal's own KDF chain construction (HMAC with a one-byte label) exactly.
- Only the *current* chain key ever persists in `localStorage`, replacing what used to be a static keypair reused for the chat's whole lifetime.
- **The actual gain**: stealing `chain_key` at some point *T* only yields message keys from *T* forward. HMAC is one-way — there is no computation that recovers `chain_key` at *T-1* from `chain_key` at *T* — so messages sent before the compromise stay unrecoverable from that stolen state. That's forward secrecy, and it's a real, meaningful improvement over the previous total-history exposure.
- **Re-keying on membership change**: whenever a participant joins or leaves, every sender's next send issues a fresh epoch (`ChainKey.epoch` increments) before deriving that message's key. A new joiner is only ever handed a wrapped seed for the epoch issued after they joined, so they can't walk the one-way chain backward to derive keys for messages sent before they arrived — the one-way property already prevents that even if they wanted to.

## What the server sees (and doesn't)

`MessageKey` now only ever holds the *sender's own* self-wrapped copy of a message's key (RSA-OAEP, unchanged from before) — kept specifically so a sender can always redisplay their own sent history after a page reload, the same way they always could. This does **not** weaken the security property being protected: forward secrecy is about an attacker who intercepts ciphertext and later steals a *recipient's* key being unable to decrypt what they intercepted — it was never about a device being unable to read messages it authored and can already see. Once a device is compromised, whatever it can already display is, definitionally, exposed; that's true of every messenger, not a gap introduced here.

Other recipients get **no per-message wrapped key at all** anymore. They derive the same message key locally by advancing their own cached copy of the sender's chain — the only thing ever transmitted for them is the one-time wrapped seed at chain-issuance time (`GetChainKeysView`). This is also a genuine efficiency win: an N-person group chat no longer needs N RSA-OAEP wrap operations per message, just one HMAC step per recipient.

## The reload problem, and how it's actually solved

A forward-secret ratchet that's genuinely discarding old keys creates an obvious tension with "reload the page and still see your message history," which this app has always supported by re-fetching ciphertext from the server and redecrypting on every load. The fix: the first time a client successfully derives a message's key via the ratchet, it caches *that specific derived key* locally, indexed by the message's own ID — not the ratchet position. A reload replays cached per-message keys for everything already seen (no ratchet involvement, no re-advancement) and only touches the live ratchet state for genuinely new messages. The ratchet's forward-secrecy property is about what's recoverable from a *stolen* snapshot of current state, not about what a legitimate, continuously-used client can still display to the person who's been reading it the whole time.

## What this explicitly does not give

This is not post-compromise security (Signal calls this "self-healing"). If an attacker obtains a participant's *current* chain key, they can derive every future message key from that sender too, until the next membership-change re-key — the ratchet only runs forward from wherever the attacker caught it. Real self-healing needs a Diffie-Hellman ratchet mixed in periodically (the other half of Signal's Double Ratchet), which requires fresh ephemeral key exchanges, not just a one-way hash chain.

That's deliberately out of scope here: hand-rolling a correct, secure multi-party DH ratchet is a genuine research-grade correctness/security risk for a solo/learning project. If Signal-equivalent post-compromise security is ever wanted, the right move is adopting a vetted library rather than extending this hand-rolled protocol further.

## What this is not

Same caveat as `docs/ACCOUNTLESS_IDENTITY.md`: this narrows a real gap, it doesn't make Telepathy ready for a high-stakes use case like source protection on its own. Key verification (TOFU/safety numbers — see issue #19) and metadata minimization remain open. See `ARCHITECTURE.md` for the full limitations list.
