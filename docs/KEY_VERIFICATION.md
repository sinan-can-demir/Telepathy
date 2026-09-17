# Key Verification: TOFU Pinning

## The gap this closes

Every trust decision in Telepathy up to this point ultimately rested on the server. A participant's `public_key`/`signing_public_key` is set once at `CreateChatView`/`JoinChatView` and then handed back verbatim by `GetChatParticipantsView` and embedded fresh on every message by `MessageSerializer`. Nothing on the client ever remembered what a participant's key looked like the last time it was seen, so a malicious or compromised server could substitute a key at any of those three points and neither the "✓ Verified" signature badge nor the transcript hash-chain would notice — both only check *internal consistency* of data the server itself supplied. A validly-signed message under an attacker's own substituted key still verifies as "valid"; verification alone was never going to catch this. That's issue #19.

## The design: trust-on-first-use (TOFU) pinning

This is the same trust model Signal, SSH, and most other systems without a central CA fall back on: you can't cryptographically prove a key belongs to the right person on first contact, but you *can* notice — and refuse to silently accept — if that key ever changes later without explanation.

- The first time this browser sees another participant's keys for a given chat, it pins the raw PEM of both keys to `localStorage`, scoped to that chat and participant (`pinned_enc_<chat>_<participant>`, `pinned_sign_<chat>_<participant>`).
- Every later fetch of the roster (`GetChatParticipantsView`, polled every 2s alongside messages) and every message's embedded `sender_signing_public_key` is compared against the pin, not just trusted at face value.
- On a mismatch, that participant is **not** auto-trusted: sending to them is blocked, and their messages are badged `⚠ Key changed` instead of `✓ Verified`, *even if the RSA-PSS signature itself checks out* — because it would, under the attacker's substituted key. Only an explicit "Trust new key" click re-pins and clears the block.
- A short fingerprint (`SHA-256(enc_key | sign_key)`, truncated and grouped like `A1B2-C3D4-E5F6-0789`) is shown in the chat header, computed from the *pinned* keys — not whatever the server just sent — so it only ever changes when the user explicitly re-trusts something. It's meant to be read aloud or compared in person, the same way the existing transcript fingerprint is.

This is entirely client-side. The point of TOFU here is specifically *not* trusting the server, so it needed no new endpoints, models, or migrations — see `chat/templates/chatbox.html`.

## What this catches

A server that substitutes a participant's key *after* the first time this browser observed it — whether at storage time, at roster-fetch time, or by lying in a single message's embedded sender key — now produces a visible, blocking warning instead of a silent, undetectable interception.

## What this explicitly does not give

- **No protection against a MITM present from message one.** TOFU's entire model is "trust whatever you see first, catch it if it changes" — if a hostile server substitutes a key from the very start of a chat, pinning that substituted key doesn't help. The fingerprint display exists precisely so participants *can* actively verify identity out-of-band (voice, in person) rather than relying on pinning alone — but nothing forces them to.
- **No cross-chat identity.** Every chat is a fresh burner identity by design (see `docs/ACCOUNTLESS_IDENTITY.md`), so there's no persistent "contact" to build trust with over time the way Signal's safety numbers can. A pin only ever protects one chat's lifetime.
- **No recovery across devices/sessions.** Pins live in this browser's `localStorage`, tied to this specific chat. Joining the same chat PIN from a second device/browser starts trust over from scratch there.

## What this is not

Same caveat as `docs/ACCOUNTLESS_IDENTITY.md` and `docs/FORWARD_SECRECY.md`: this narrows a real gap, it doesn't make Telepathy ready for a high-stakes use case like source protection on its own. Metadata minimization remains open. See `ARCHITECTURE.md` for the full limitations list.
