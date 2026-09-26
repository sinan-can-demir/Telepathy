# Key Verification: TOFU Pinning

## The gap this closes

Every trust decision in Telepathy up to this point ultimately rested on the server. A participant's `public_key` is set once at `CreateChatView`/`JoinChatView` and then handed back verbatim by `GetChatParticipantsView` and embedded fresh on every message by `MessageSerializer`. Nothing on the client ever remembered what a participant's key looked like the last time it was seen, so a malicious or compromised server could substitute a key at any of those three points and neither the "✓ Verified" MAC badge nor the transcript hash-chain would notice — both only check *internal consistency* of data the server itself supplied. A validly-MAC'd message under an attacker's own substituted key still verifies as "valid"; verification alone was never going to catch this. That's issue #19.

## The design: trust-on-first-use (TOFU) pinning

This is the same trust model Signal, SSH, and most other systems without a central CA fall back on: you can't cryptographically prove a key belongs to the right person on first contact, but you *can* notice — and refuse to silently accept — if that key ever changes later without explanation.

- The first time this browser sees another participant's public key for a given chat, it pins the raw PEM to `localStorage`, scoped to that chat and participant (`pinned_enc_<chat>_<participant>`).
- Every later fetch of the roster (`GetChatParticipantsView`, polled every 2s alongside messages) and every message's embedded `sender_public_key` is compared against the pin, not just trusted at face value.
- On a mismatch, that participant is **not** auto-trusted: sending to them is blocked, and their messages are badged `⚠ Key changed` instead of `✓ Verified`, *even if the MAC itself checks out* — because it would, under the attacker's substituted key (whoever holds the substituted encryption key also controls what chain-key seed gets wrapped to this browser, so they can produce a MAC that verifies against their own substituted chain too). Only an explicit "Trust new key" click re-pins and clears the block.
- A short fingerprint (`SHA-256(enc_key)`, truncated and grouped like `A1B2-C3D4-E5F6-0789`) is shown in the chat header, computed from the *pinned* key — not whatever the server just sent — so it only ever changes when the user explicitly re-trusts something. It's meant to be read aloud or compared in person, the same way the existing transcript fingerprint is.

This is entirely client-side. The point of TOFU here is specifically *not* trusting the server, so it needed no new endpoints, models, or migrations — see `chat/templates/chatbox.html`.

**Note (issue #61):** this previously also pinned a separate `signing_public_key` and folded it into the fingerprint. There's only one key to pin now — see `docs/DENIABLE_AUTH.md` for why the signing keypair was removed rather than kept alongside a MAC.

## What this catches

A server that substitutes a participant's key *after* the first time this browser observed it — whether at storage time, at roster-fetch time, or by lying in a single message's embedded sender key — now produces a visible, blocking warning instead of a silent, undetectable interception.

## Fingerprint gate (#100)

Joining a chat needs no approval from its members, and every member's next send re-keys to include whoever is in the roster. So before this browser sends anything to a participant, it now requires the user to confirm they compared that participant's fingerprint out of band:

- A banner lists each participant not yet confirmed, with the fingerprint this browser sees for them, and the user's **own** fingerprint (so the other side can compare it too; previously only the other participant's was shown).
- Sending is blocked while anyone in the recipient list is unconfirmed. The check runs before the chain key is (re-)issued, so no seed is ever wrapped to an unconfirmed participant.
- A confirmation is stored as the confirmed fingerprint (`fp_ack_<chat>_<participant>` in `localStorage`), so a key that later changes and is re-trusted through the mismatch banner needs a fresh comparison. It is wiped with the rest of the chat's local state.
- Join and leave notices appear in the transcript, and names are unique per chat (case-insensitive), so an intruder can't wear an existing member's name.

It's a speed bump that makes the comparison explicit, not a proof that it happened.

## What this explicitly does not give

- **No protection against a MITM present from message one.** TOFU's entire model is "trust whatever you see first, catch it if it changes" — if a hostile server substitutes a key from the very start of a chat, pinning that substituted key doesn't help. The fingerprint comparison is what catches it, and since #100 it is a required step rather than an option (see "Fingerprint gate" below). It still only works if people actually compare over a channel the server doesn't control; clicking "They match" without comparing gives no protection.
- **No cross-chat identity.** Every chat is a fresh burner identity by design (see `docs/ACCOUNTLESS_IDENTITY.md`), so there's no persistent "contact" to build trust with over time the way Signal's safety numbers can. A pin only ever protects one chat's lifetime.
- **No recovery across devices/sessions.** Pins live in this browser's `localStorage`, tied to this specific chat. Joining the same chat PIN from a second device/browser starts trust over from scratch there.

## What this is not

Same caveat as `docs/ACCOUNTLESS_IDENTITY.md` and `docs/FORWARD_SECRECY.md`: this narrows a real gap, it doesn't make Telepathy ready for a high-stakes use case like source protection on its own. Metadata minimization remains open. See `ARCHITECTURE.md` for the full limitations list.
